from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import Response

from secmind.artifact_store import ArtifactAccessMetadata, ArtifactStoreError
from secmind.investigation.store import InvestigationAccessDenied
from secmind.log_governance import authorize_data_view
from secmind.runtime import ApplicationRuntime
from secmind.schemas import DataView, LogLayer

_ARTIFACT_ID = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True, slots=True)
class AuthorizedArtifact:
    data_view: DataView
    access_id: str
    media_type: str


class ArtifactDownloadPolicy:
    """Resolve run binding, classification and append-only access audit once."""

    def __init__(self, runtime: ApplicationRuntime) -> None:
        self.runtime = runtime

    def authorize(
        self,
        *,
        run_id: str,
        artifact_id: str,
        requested_view: DataView | None,
        purpose: str | None,
    ) -> AuthorizedArtifact:
        if not _ARTIFACT_ID.fullmatch(artifact_id):
            raise HTTPException(404, "Artifact not found")
        try:
            state = self.runtime.service.state(run_id)
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc

        allowed = {item for step in state.step_runtime.values() for item in step.artifact_ids}
        allowed.update(artifact.artifact_id for observation in state.observations for artifact in observation.artifacts)
        allowed.update(evidence.artifact_ref for evidence in state.evidence if evidence.artifact_ref is not None)
        # InputArtifact.artifact_id is a logical UUID in the normal ingest path,
        # while this route deliberately accepts only immutable content digests.
        # Bind the CAS identity explicitly so genuine input bytes are reachable
        # without weakening the path contract to accept mutable identifiers.
        allowed.update(item.sha256.lower() for item in state.input_artifacts)
        if state.replay_bundle is not None:
            allowed.add(state.replay_bundle.artifact_id)
        if artifact_id not in allowed:
            self._audit(
                run_id,
                artifact_id,
                requested_view or DataView.OBSERVABLE,
                purpose,
                "denied",
                "ARTIFACT_NOT_BOUND_TO_RUN",
            )
            raise HTTPException(404, "Artifact not found")

        try:
            metadata = self.runtime.service.artifact_store.metadata_for(artifact_id)
        except FileNotFoundError as exc:
            self._audit(
                run_id,
                artifact_id,
                requested_view or DataView.OBSERVABLE,
                purpose,
                "denied",
                "ARTIFACT_NOT_FOUND",
            )
            raise HTTPException(409, "Artifact failed integrity verification") from exc
        except ArtifactStoreError as exc:
            self._audit(
                run_id,
                artifact_id,
                requested_view or DataView.OBSERVABLE,
                purpose,
                "denied",
                "ARTIFACT_METADATA_INVALID",
            )
            raise HTTPException(409, "Artifact access metadata failed verification") from exc

        input_ids = {
            reference for item in state.input_artifacts for reference in (item.artifact_id, item.sha256.lower())
        }
        is_input = artifact_id in input_ids
        effective_view = DataView.RAW_RESTRICTED if is_input else metadata.data_view
        effective_layer = LogLayer.RAW_SECURITY if is_input else metadata.log_layer
        bound_run_ids = set(metadata.run_ids)
        if is_input or metadata.globally_bound:
            bound_run_ids.add(run_id)

        self._validate_request(
            run_id=run_id,
            artifact_id=artifact_id,
            requested_view=requested_view,
            effective_view=effective_view,
            purpose=purpose,
        )
        decision = authorize_data_view(
            run_id=run_id,
            requested_view=effective_view,
            actor_id="operator",
            actor_role="operator",
            bound_run_ids=frozenset(bound_run_ids),
            details={
                "artifact_id": artifact_id,
                "layer": None if effective_layer is None else effective_layer.value,
                "purpose": purpose or "artifact_download",
            },
        )
        if not decision.allowed:
            self._audit(run_id, artifact_id, effective_view, purpose, "denied", decision.reason_code)
            raise HTTPException(403, decision.reason_code)
        # ArtifactSecurityLabel is the server-owned purpose policy.  The client
        # supplied purpose is audit context only; it must never turn a raw
        # analysis/forensics grant into a download grant.  Run binding is checked
        # first so denied cross-run access keeps its precise audit reason.
        investigation_store = self.runtime.service.investigation_store
        if not is_input and investigation_store is not None:
            try:
                investigation_store.authorize_artifact(artifact_id, run_id=run_id, purpose="download")
            except InvestigationAccessDenied as exc:
                self._audit(
                    run_id,
                    artifact_id,
                    effective_view,
                    purpose,
                    "denied",
                    "ARTIFACT_DOWNLOAD_NOT_AUTHORIZED",
                )
                raise HTTPException(403, "Artifact security label does not permit download") from exc
        access_id = self._audit(run_id, artifact_id, effective_view, purpose, "allowed", decision.reason_code)
        return AuthorizedArtifact(
            data_view=effective_view,
            access_id=access_id,
            media_type=self._media_type(state, metadata, artifact_id),
        )

    def _validate_request(
        self,
        *,
        run_id: str,
        artifact_id: str,
        requested_view: DataView | None,
        effective_view: DataView,
        purpose: str | None,
    ) -> None:
        if effective_view == DataView.RAW_RESTRICTED and requested_view != DataView.RAW_RESTRICTED:
            self._audit(run_id, artifact_id, effective_view, purpose, "denied", "EXPLICIT_RAW_VIEW_REQUIRED")
            raise HTTPException(403, "Raw artifact access requires view=raw_restricted")
        if requested_view is not None and requested_view != effective_view:
            self._audit(run_id, artifact_id, effective_view, purpose, "denied", "ARTIFACT_VIEW_MISMATCH")
            raise HTTPException(403, "Requested DataView does not match artifact classification")
        if effective_view == DataView.RAW_RESTRICTED and not (purpose or "").strip():
            self._audit(run_id, artifact_id, effective_view, purpose, "denied", "RAW_ACCESS_PURPOSE_REQUIRED")
            raise HTTPException(403, "Raw artifact access requires X-SecMind-Access-Purpose")

    def _audit(
        self,
        run_id: str,
        artifact_id: str,
        view: DataView,
        purpose: str | None,
        decision: str,
        reason_code: str,
    ) -> str:
        unit_of_work = self.runtime.service.unit_of_work
        if unit_of_work is None:
            raise HTTPException(503, "Artifact access audit store is unavailable")
        try:
            return unit_of_work.record_data_access_event(
                run_id=run_id,
                actor="operator",
                view=view,
                resource_type="artifact",
                resource_id=artifact_id,
                purpose=purpose or "artifact_download",
                decision=decision,
                reason_code=reason_code,
            )
        except (KeyError, RuntimeError, ValueError) as exc:
            raise HTTPException(503, "Artifact access audit could not be persisted") from exc

    @staticmethod
    def _media_type(state: Any, metadata: ArtifactAccessMetadata, artifact_id: str) -> str:
        return next(
            (
                artifact.media_type
                for observation in state.observations
                for artifact in observation.artifacts
                if artifact.artifact_id == artifact_id
            ),
            next(
                (
                    item.media_type
                    for item in state.input_artifacts
                    if artifact_id in {item.artifact_id, item.sha256.lower()}
                ),
                metadata.media_type,
            ),
        )


def register_artifact_routes(app: FastAPI, runtime: ApplicationRuntime) -> None:
    policy = ArtifactDownloadPolicy(runtime)

    @app.get("/api/v1/runs/{run_id}/artifacts/{artifact_id}")
    async def download_artifact(
        request: Request,
        run_id: str,
        artifact_id: str,
        view: Annotated[DataView | None, Query()] = None,
        purpose: Annotated[str | None, Header(alias="X-SecMind-Access-Purpose", max_length=200)] = None,
    ) -> Response:
        access = policy.authorize(
            run_id=run_id,
            artifact_id=artifact_id,
            requested_view=view,
            purpose=purpose,
        )
        headers = {
            "X-SecMind-Access-Id": access.access_id,
            "X-SecMind-Data-View": access.data_view.value,
        }
        if access.data_view == DataView.RAW_RESTRICTED:
            return Response(
                _read_artifact(runtime, artifact_id),
                media_type=access.media_type,
                headers={**headers, "Cache-Control": "private, no-store"},
            )

        etag = f'"sha256:{artifact_id}"'
        cache_headers = {**headers, "ETag": etag, "Cache-Control": "private, immutable"}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=cache_headers)
        return Response(
            _read_artifact(runtime, artifact_id),
            media_type=access.media_type,
            headers=cache_headers,
        )


def _read_artifact(runtime: ApplicationRuntime, artifact_id: str) -> bytes:
    try:
        return runtime.service.artifact_store.read(artifact_id)
    except (FileNotFoundError, ArtifactStoreError) as exc:
        raise HTTPException(409, "Artifact failed integrity verification") from exc


__all__ = ["ArtifactDownloadPolicy", "register_artifact_routes"]
