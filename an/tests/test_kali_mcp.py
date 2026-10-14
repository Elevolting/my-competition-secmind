"""The Kali adapters must keep caller input out of command and file selection."""
import pytest

from security_agent import kali_mcp
from security_agent.mcp_approval import requires_approval


@pytest.mark.asyncio
async def test_new_scanners_use_fixed_commands_and_require_approval(monkeypatch):
    calls = []

    async def fake_run(tool, args, timeout=70):
        calls.append((tool, args, timeout))
        return {"tool": tool, "returncode": 0, "output": "", "stderr": ""}

    monkeypatch.setattr(kali_mcp, "_run", fake_run)
    target = "https://target.test/app/"
    await kali_mcp.nuclei_scan("https://target.test/")
    await kali_mcp.ffuf_directory(target)
    await kali_mcp.nikto_scan("https://target.test/")
    await kali_mcp.dirsearch_scan(target)
    await kali_mcp.gobuster_directory(target)
    await kali_mcp.sqlmap_audit("https://target.test/app?id=1")

    assert [item[0] for item in calls] == [
        "nuclei", "ffuf", "nikto", "dirsearch", "gobuster", "sqlmap",
    ]
    for tool, args, _ in calls:
        assert requires_approval("kali-tools", {
            "ffuf": "ffuf_directory", "nikto": "nikto_scan",
            "nuclei": "nuclei_scan", "dirsearch": "dirsearch_scan",
            "gobuster": "gobuster_directory", "sqlmap": "sqlmap_audit",
        }[tool], {"target": target})
        assert all("outside.test" not in item for item in args)
    nuclei = calls[0][1]
    assert "-no-interactsh" in nuclei and "-disable-redirects" in nuclei
    assert "-no-stdin" in nuclei
    assert "/opt/secmind/nuclei-http-headers.yaml" in nuclei
    assert calls[1][1][1] == "https://target.test/app/FUZZ"
    for _, args, _ in (calls[1], calls[3], calls[4]):
        assert "/opt/secmind/common-paths.txt" in args
    assert "--ignore-redirects" in calls[5][1]


@pytest.mark.asyncio
async def test_new_scanners_reject_file_and_cross_scope_inputs_before_execution(monkeypatch):
    async def unexpected_run(*_args, **_kwargs):
        pytest.fail("invalid arguments reached Docker")

    monkeypatch.setattr(kali_mcp, "_run", unexpected_run)
    with pytest.raises(ValueError):
        await kali_mcp.ffuf_directory("https://target.test/app?next=https://outside.test/")
    with pytest.raises(ValueError):
        await kali_mcp.ffuf_directory("https://target.test/app", wordlist="other.txt")
    with pytest.raises(ValueError):
        await kali_mcp.dirsearch_scan("file:///etc/passwd")
    with pytest.raises(ValueError):
        await kali_mcp.gobuster_directory("https://target.test/app?x=1")
    with pytest.raises(ValueError):
        await kali_mcp.nuclei_scan("https://target.test/", severity="critical,invalid")
    with pytest.raises(ValueError):
        await kali_mcp.sqlmap_audit("https://target.test@outside.test/")


@pytest.mark.asyncio
async def test_new_tools_can_report_installed_versions(monkeypatch):
    calls = []

    async def fake_run(tool, args, timeout=70):
        calls.append((tool, args))
        return {"tool": tool, "returncode": 0, "output": "1.0", "stderr": ""}

    monkeypatch.setattr(kali_mcp, "_run", fake_run)
    for name in ("ffuf", "nikto", "dirsearch", "gobuster", "sqlmap"):
        await kali_mcp.kali_tool_version(name)
    assert [name for name, _ in calls] == ["ffuf", "nikto", "dirsearch", "gobuster", "sqlmap"]
