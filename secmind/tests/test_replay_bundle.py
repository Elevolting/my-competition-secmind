from __future__ import annotations

import hashlib
import io
import json
import warnings
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.ledger import ZERO_HASH, LedgerStore
from secmind.replay import (
    REQUIRED_REPLAY_ENTRIES,
    LedgerHeadSigner,
    ReplayEntry,
    ReplayError,
    ReplayManager,
)
from secmind.schemas import ReplayBundleRef
from secmind.unit_of_work import CognitiveBase, ReplayBundleRow


def _replay_entries(ledger_content: bytes, *, include_patch: bool = True) -> list[ReplayEntry]:
    entries: list[ReplayEntry] = []
    for path in sorted(REQUIRED_REPLAY_ENTRIES):
        if path == "ledger.jsonl":
            content = ledger_content
        elif path == "report.md":
            content = b"# Report\n"
        elif path.endswith(".jsonl"):
            content = b""
        else:
            content = b"{}"
        entries.append(ReplayEntry(path, content))
    if include_patch:
        entries.append(
            ReplayEntry(
                "step-patches.jsonl",
                b'{"status":"succeeded","step_id":"scan"}\n',
                "application/x-ndjson",
            )
        )
    return entries


def _ledger_fixture(tmp_path):
    url = f"sqlite:///{(tmp_path / 'ledger.db').as_posix()}"
    ledger = LedgerStore(url)
    event = ledger.append("run-replay", "run.completed", {"status": "completed"}, dedupe_key="complete")
    content = (event.model_dump_json() + "\n").encode()
    return ledger, event, content


def _archive_bytes(entries: dict[str, bytes], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for path, content in entries.items():
            archive.writestr(path, content)
    return output.getvalue()


def _unverified_ref(store: ContentAddressedArtifactStore, archive: bytes) -> ReplayBundleRef:
    stored = store.put(archive)
    return ReplayBundleRef(
        run_id="run",
        artifact_id=stored.artifact_id,
        manifest_digest="0" * 64,
        ledger_head_hash=ZERO_HASH,
    )


def test_build_verify_and_deterministic_replay_use_no_models_or_tools(tmp_path) -> None:
    ledger, head, ledger_content = _ledger_fixture(tmp_path)
    engine = ledger.engine
    CognitiveBase.metadata.create_all(engine)
    artifact_store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    key = Ed25519PrivateKey.generate()
    signer = LedgerHeadSigner("ledger-release-v1", key)
    manager = ReplayManager(
        artifact_store,
        engine=engine,
        ledger_signer=signer,
        trusted_ledger_signers={"ledger-release-v1": signer.public_key()},
    )

    replay_ref = manager.build(
        run_id="run-replay",
        entries=_replay_entries(ledger_content),
        ledger_head_hash=head.hash,
    )
    verification = manager.verify_only(replay_ref)
    replayed = manager.deterministic_replay(replay_ref)

    assert replay_ref.artifact_id == hashlib.sha256(artifact_store.read(replay_ref.artifact_id)).hexdigest()
    assert verification.ledger_head_hash == head.hash
    assert verification.model_calls == verification.tool_calls == 0
    assert replayed.model_calls == replayed.tool_calls == 0
    assert replayed.final_sequence == 1
    assert replayed.step_patches == ({"status": "succeeded", "step_id": "scan"},)
    assert ledger.verify("run-replay")
    with Session(engine) as session:
        assert session.scalars(select(ReplayBundleRow)).one().artifact_id == replay_ref.artifact_id


def test_replay_build_is_content_addressed_and_database_idempotent(tmp_path) -> None:
    ledger, head, ledger_content = _ledger_fixture(tmp_path)
    CognitiveBase.metadata.create_all(ledger.engine)
    manager = ReplayManager(
        ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024),
        engine=ledger.engine,
    )
    first = manager.build(run_id="run-replay", entries=_replay_entries(ledger_content), ledger_head_hash=head.hash)
    second = manager.build(run_id="run-replay", entries=_replay_entries(ledger_content), ledger_head_hash=head.hash)

    assert second.artifact_id == first.artifact_id
    assert second.manifest_digest == first.manifest_digest
    assert second.replay_id == first.replay_id
    with Session(ledger.engine) as session:
        assert len(session.scalars(select(ReplayBundleRow)).all()) == 1


def test_replay_rejects_missing_duplicate_traversal_and_tampered_ledger(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    manager = ReplayManager(store)
    with pytest.raises(ReplayError, match="incomplete"):
        manager.build(
            run_id="run",
            entries=[ReplayEntry("report.json", b"{}")],
            ledger_head_hash=ZERO_HASH,
        )
    with pytest.raises(ReplayError, match="not canonical"):
        manager.build(
            run_id="run",
            entries=[ReplayEntry("../report.json", b"{}")],
            ledger_head_hash=ZERO_HASH,
        )
    entries = _replay_entries(b"")
    entries.append(ReplayEntry("report.json", b"{}"))
    with pytest.raises(ReplayError, match="duplicate"):
        manager.build(run_id="run", entries=entries, ledger_head_hash=ZERO_HASH)

    bad_event = {
        "event_id": "e",
        "run_id": "run",
        "sequence": 1,
        "event_type": "bad",
        "timestamp": "2026-01-01T00:00:00Z",
        "actor": "test",
        "dedupe_key": "bad",
        "payload": {},
        "prev_hash": ZERO_HASH,
        "hash": "f" * 64,
    }
    with pytest.raises(ReplayError, match="hash chain"):
        manager.build(
            run_id="run",
            entries=_replay_entries((json.dumps(bad_event) + "\n").encode()),
            ledger_head_hash="f" * 64,
        )


def test_verify_rejects_duplicate_zip_entries_before_extraction(tmp_path) -> None:
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("manifest.json", b"{}")
            archive.writestr("manifest.json", b"{}")
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    stored = store.put(output.getvalue())
    manager = ReplayManager(store)
    replay_ref = ReplayBundleRef(
        run_id="run",
        artifact_id=stored.artifact_id,
        manifest_digest="0" * 64,
        ledger_head_hash=ZERO_HASH,
    )
    with pytest.raises(ReplayError, match="duplicate entries"):
        manager.verify_only(replay_ref)


def test_ledger_head_signature_requires_trusted_key_and_exact_binding(tmp_path) -> None:
    ledger, head, ledger_content = _ledger_fixture(tmp_path)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    signer = LedgerHeadSigner("trusted", Ed25519PrivateKey.generate())
    builder = ReplayManager(store, ledger_signer=signer)
    replay_ref = builder.build(
        run_id="run-replay",
        entries=_replay_entries(ledger_content),
        ledger_head_hash=head.hash,
    )

    with pytest.raises(ReplayError, match="not trusted"):
        builder.verify_only(replay_ref)
    verifier = ReplayManager(store, trusted_ledger_signers={"trusted": signer.public_key()})
    assert verifier.verify_only(replay_ref).ledger_head_hash == head.hash
    tampered = replay_ref.model_copy(update={"run_id": "other-run"})
    with pytest.raises(ReplayError, match="different run"):
        verifier.verify_only(tampered)


def test_replay_configuration_and_build_limits_are_enforced(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    with pytest.raises(ValueError, match="limits"):
        ReplayManager(store, max_entry_bytes=0)
    with pytest.raises(ValueError, match="key id"):
        LedgerHeadSigner("bad key", Ed25519PrivateKey.generate())

    manager = ReplayManager(store, max_entry_bytes=8, max_bundle_bytes=256)
    with pytest.raises(ReplayError, match="valid ledger head"):
        manager.build(run_id="", entries=[], ledger_head_hash="bad")
    with pytest.raises(ReplayError, match="not allowlisted"):
        manager.build(
            run_id="run",
            entries=[ReplayEntry("unknown.json", b"{}")],
            ledger_head_hash=ZERO_HASH,
        )
    with pytest.raises(ReplayError, match="entry exceeds"):
        manager.build(
            run_id="run",
            entries=[ReplayEntry("report.json", b"x" * 9)],
            ledger_head_hash=ZERO_HASH,
        )

    total_limited = ReplayManager(store, max_entry_bytes=8, max_bundle_bytes=8)
    with pytest.raises(ReplayError, match="bundle exceeds"):
        total_limited.build(
            run_id="run",
            entries=[ReplayEntry("report.json", b"12345678"), ReplayEntry("report.md", b"1")],
            ledger_head_hash=ZERO_HASH,
        )


def test_replay_build_rejects_cross_run_wrong_head_and_invalid_ledger_rows(tmp_path) -> None:
    _ledger, head, ledger_content = _ledger_fixture(tmp_path)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    manager = ReplayManager(store)
    with pytest.raises(ReplayError, match="different run"):
        manager.build(run_id="other", entries=_replay_entries(ledger_content), ledger_head_hash=head.hash)
    with pytest.raises(ReplayError, match="declared chain head"):
        manager.build(run_id="run-replay", entries=_replay_entries(ledger_content), ledger_head_hash="f" * 64)

    event = json.loads(ledger_content)
    event["sequence"] = 2
    with pytest.raises(ReplayError, match="sequence"):
        manager.build(
            run_id="run-replay",
            entries=_replay_entries((json.dumps(event) + "\n").encode()),
            ledger_head_hash=head.hash,
        )
    with pytest.raises(ReplayError, match="invalid event"):
        manager.build(
            run_id="run-replay",
            entries=_replay_entries(b'{"not":"an event"}\n'),
            ledger_head_hash=head.hash,
        )


@pytest.mark.parametrize(
    ("archive", "message"),
    [
        (b"not-a-zip", "valid archive"),
        (_archive_bytes({"report.json": b"{}"}), "no manifest"),
        (_archive_bytes({"manifest.json": b"not-json"}), "invalid JSON"),
        (_archive_bytes({"manifest.json": b'{"z":1, "a":2}'}), "canonical JSON"),
        (
            _archive_bytes({"manifest.json": b"{}", "../report.json": b"{}"}),
            "not canonical",
        ),
        (
            _archive_bytes({"manifest.json": b"{}"}, compression=zipfile.ZIP_DEFLATED),
            "stored compression",
        ),
    ],
)
def test_replay_archive_rejects_malformed_and_unsafe_zip_entries(tmp_path, archive: bytes, message: str) -> None:
    store = ContentAddressedArtifactStore(tmp_path / message.replace(" ", "-"))
    manager = ReplayManager(store)
    with pytest.raises(ReplayError, match=message):
        manager.verify_only(_unverified_ref(store, archive))


def test_verify_rejects_reference_metadata_tampering(tmp_path) -> None:
    _ledger, head, ledger_content = _ledger_fixture(tmp_path)
    store = ContentAddressedArtifactStore(tmp_path / "artifacts", max_artifact_bytes=64 * 1024 * 1024)
    manager = ReplayManager(store)
    replay_ref = manager.build(
        run_id="run-replay",
        entries=_replay_entries(ledger_content),
        ledger_head_hash=head.hash,
        parent_run_id="parent",
    )

    mutations = [
        ({"manifest_digest": "f" * 64}, "manifest digest"),
        ({"parent_run_id": "other-parent"}, "parent run"),
        ({"ledger_head_hash": "f" * 64}, "head metadata"),
        ({"ledger_head_signature": "untrusted.value"}, "signature metadata"),
    ]
    for update, message in mutations:
        with pytest.raises(ReplayError, match=message):
            manager.verify_only(replay_ref.model_copy(update=update))


def test_signature_decoder_rejects_malformed_untrusted_and_invalid_signatures(tmp_path) -> None:
    store = ContentAddressedArtifactStore(tmp_path / "artifacts")
    trusted = LedgerHeadSigner("trusted", Ed25519PrivateKey.generate())
    manager = ReplayManager(store, trusted_ledger_signers={"trusted": trusted.public_key()})
    with pytest.raises(ReplayError, match="malformed"):
        manager._verify_ledger_signature("run", ZERO_HASH, "missing-separator")
    with pytest.raises(ReplayError, match="not trusted"):
        manager._verify_ledger_signature("run", ZERO_HASH, "other.AA")
    with pytest.raises(ReplayError, match="encoding is not canonical"):
        manager._verify_ledger_signature("run", ZERO_HASH, "trusted.=")
    with pytest.raises(ReplayError, match="signature is invalid"):
        manager._verify_ledger_signature("run", ZERO_HASH, "trusted.AA")


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        (b"\xff", "UTF-8"),
        (b"not-json\n", "invalid JSON"),
        (b"[]\n", "JSON object"),
    ],
)
def test_deterministic_replay_rejects_invalid_stored_step_patches(
    tmp_path,
    patch: bytes,
    message: str,
) -> None:
    _ledger, head, ledger_content = _ledger_fixture(tmp_path)
    store = ContentAddressedArtifactStore(tmp_path / message.replace(" ", "-"), max_artifact_bytes=64 * 1024 * 1024)
    manager = ReplayManager(store)
    entries = _replay_entries(ledger_content, include_patch=False)
    entries.append(ReplayEntry("step-patches.jsonl", patch))
    replay_ref = manager.build(run_id="run-replay", entries=entries, ledger_head_hash=head.hash)
    with pytest.raises(ReplayError, match=message):
        manager.deterministic_replay(replay_ref)
