from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PACKAGED_RULES = "docker/tools/semgrep/rules/reviewed"


def test_runtime_images_copy_forced_package_inputs_before_sync() -> None:
    for relative_path in ("Dockerfile", "docker/sandbox/Dockerfile"):
        dockerfile = (_ROOT / relative_path).read_text(encoding="utf-8")
        copy_position = dockerfile.index(f"COPY {_PACKAGED_RULES} ")
        sync_position = dockerfile.index("RUN uv sync")

        assert copy_position < sync_position, (
            f"{relative_path} must copy Hatch force-included Semgrep rules before installing the project"
        )


def test_ci_and_bootstrap_pin_enabled_semgrep_inputs() -> None:
    workflow = (_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    bootstrap = (_ROOT / "scripts/bootstrap-docker.ps1").read_text(encoding="utf-8")

    assert "docker/tools/semgrep/Dockerfile" in workflow
    assert "docker image inspect secmind-semgrep:local" in workflow
    assert "build semgrep-tool" in bootstrap
    assert "docker image inspect secmind-semgrep:local" in bootstrap
    for deployment_source in (workflow, bootstrap):
        assert "SECMIND_SANDBOX_SEMGREP_IMAGE" in deployment_source
        assert "SECMIND_SEMGREP_SAST_RULE_BUNDLE_DIGEST" in deployment_source
