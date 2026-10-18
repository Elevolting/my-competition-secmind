from __future__ import annotations

import hashlib
from pathlib import Path

from secmind.canonical_primary import (
    CANONICAL_PRIMARY_PROMPT_VERSION,
    CanonicalAnalysisContract,
    CanonicalPrimaryResult,
    UniversalFinding,
    UniversalPrimaryAnswer,
    canonical_system_prompt,
    project_canonical_result,
)
from secmind.llm import ModelCallMeta
from secmind.primary_claim_gate import gate_primary_claims
from secmind.schemas import InputArtifact, ModelUsage


def _finding(**updates: object) -> UniversalFinding:
    values: dict[str, object] = {
        "title": "Candidate",
        "cwe": 248,
        "severity": "LOW",
        "confidence": 0.8,
        "path": "src/App.java",
        "line": 4,
        "evidence_excerpt": "throw new IllegalArgumentException(input);",
        "data_flow": "request input -> exception",
        "root_cause": "Malformed input raises an exception.",
        "impact": "The current request fails.",
    }
    values.update(updates)
    return UniversalFinding.model_validate(values)


def test_low_per_request_cwe248_is_rejected_without_mutating_primary() -> None:
    claim = _finding()
    before = claim.model_dump(mode="json")

    result = gate_primary_claims(
        [claim],
        {"src/App.java": "void handle(String input) { throw new IllegalArgumentException(input); }"},
    )

    assert result.admitted == ()
    assert result.folded == ()
    assert result.rejected[0].claim_index == 0
    assert result.rejected[0].reason_code == "cwe_248_lacks_material_scope_or_leakage"
    assert claim.model_dump(mode="json") == before


def test_cwe248_with_process_wide_or_sensitive_leakage_proof_is_admitted() -> None:
    process_wide = _finding(
        line=1,
        impact="Malformed input terminates the process and causes persistent denial of service.",
    )
    leakage = _finding(line=1, impact="The response discloses a sensitive exception message.")

    process_result = gate_primary_claims(
        [process_wide],
        {"src/App.java": "void handle(String input) { if (bad(input)) System.exit(1); }"},
    )
    leakage_result = gate_primary_claims(
        [leakage],
        {
            "src/App.java": (
                "try { parse(input); } catch (Exception error) { response.getWriter().write(error.getMessage()); }"
            )
        },
    )

    assert [item.claim_index for item in process_result.admitted] == [0]
    assert [item.claim_index for item in leakage_result.admitted] == [0]
    assert not process_result.rejected
    assert not leakage_result.rejected


def test_cwe248_with_cross_request_failure_state_is_admitted() -> None:
    claim = _finding(line=5, impact="One exception poisons shared state and makes later requests unavailable.")
    source = """
private static volatile boolean unavailable;
void handle(String input) {
    try { parse(input); }
    catch (Exception error) { unavailable = true; }
}
"""

    result = gate_primary_claims([claim], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()


def test_cwe248_python_exception_return_is_sensitive_leakage_proof() -> None:
    claim = _finding(
        path="app.py",
        line=3,
        impact="The response leaks a sensitive internal exception message.",
    )
    source = "def handle(value):\n    try: parse(value)\n    except Exception as exc: return str(exc)\n"

    result = gate_primary_claims([claim], {"app.py": source})

    assert [item.claim_index for item in result.admitted] == [0]


def test_runtime_contingent_cookie_header_claim_is_not_published() -> None:
    claim = _finding(
        cwe=113,
        path="subject.java",
        line=2,
        evidence_excerpt='new Cookie("SomeCookie", value)',
        data_flow="request header -> Cookie value -> response.addCookie",
        preconditions="Exploitation works if the servlet container does not reject CR/LF characters.",
        impact="Depending on runtime behavior, response splitting may be possible.",
    )
    source = 'Cookie cookie = new Cookie("SomeCookie", value);\nresponse.addCookie(cookie);\n'

    result = gate_primary_claims([claim], {"subject.java": source})

    assert result.admitted == ()
    assert result.rejected[0].reason_code == "cwe_113_depends_on_unsupplied_runtime_behavior"


def test_runtime_contingent_cookie_claim_handles_must_without_wording() -> None:
    claim = _finding(
        cwe="CWE-113",
        path="subject.java",
        title="Conditional response header injection",
        evidence_excerpt='new Cookie("SomeCookie", value); response.addCookie(cookie);',
        data_flow="request header -> Cookie value -> response.addCookie",
        preconditions=(
            "The servlet container must serialize the Cookie value without rejecting CR/LF; "
            "modern containers may reject the value instead."
        ),
        impact="Response splitting is possible only under that runtime behavior.",
    )
    source = 'Cookie cookie = new Cookie("SomeCookie", value); response.addCookie(cookie);'

    result = gate_primary_claims([claim], {"subject.java": source})

    assert result.admitted == ()
    assert result.rejected[0].reason_code == "cwe_113_depends_on_unsupplied_runtime_behavior"


def test_direct_header_write_is_not_hidden_by_cookie_precision_rule() -> None:
    claim = _finding(
        cwe=113,
        path="subject.java",
        line=2,
        preconditions="Exploitation works if the server allows CR/LF characters.",
    )
    source = 'Cookie cookie = new Cookie("SomeCookie", value);\nresponse.addHeader("X-Subject", value);\n'

    result = gate_primary_claims([claim], {"subject.java": source})

    assert [item.claim_index for item in result.admitted] == [0]


def test_unproven_ui_only_credential_exposure_is_not_published() -> None:
    claim = _finding(
        cwe=522,
        path="wireless.lua",
        line=3,
        title="Key material is handled by unmasked editable fields",
        evidence_excerpt='r1kh = section:taboption("encryption", DynamicList, "r1kh")',
        data_flow="Configured key material flows into an ordinary DynamicList control.",
        root_cause="Unlike other secrets, the editable field is not password-masked.",
        preconditions=(
            "Disclosure is exploitable only if the CBI renderer displays the value or an unauthorized principal "
            "can access the configuration. Those access controls were not supplied."
        ),
        impact="Unauthorized disclosure is not established from this file alone.",
    )

    result = gate_primary_claims(
        [claim],
        {"wireless.lua": 'r1kh = section:taboption("encryption", DynamicList, "r1kh")'},
    )

    assert result.admitted == ()
    assert result.rejected[0].reason_code == ("cwe_522_ui_exposure_depends_on_unprovided_renderer_or_authorization")


def test_proven_credential_disclosure_is_not_hidden_by_ui_precision_rule() -> None:
    claim = _finding(
        cwe=522,
        path="account.py",
        line=2,
        title="Credential is returned to an unauthorized caller",
        evidence_excerpt='return {"password": account.password}',
        data_flow="stored password -> unauthenticated API response",
        root_cause="The endpoint serializes the stored credential without an authorization check.",
        preconditions="The route is publicly reachable according to the supplied router.",
        impact="An unauthenticated principal obtains the stored credential.",
    )

    result = gate_primary_claims(
        [claim],
        {"account.py": 'def account():\n    return {"password": account.password}\n'},
    )

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()


def test_source_local_csrf_hypothesis_survives_unseen_middleware_uncertainty() -> None:
    claim = _finding(
        cwe=352,
        path="subject.php",
        line=37,
        title="Direct password-change action lacks visible CSRF protection",
        data_flow="POST step=2 -> password update",
        preconditions=(
            "The application must use ambient browser credentials and lack CSRF protection in unseen routing or "
            "middleware. Those framework-level conditions are not provided."
        ),
        impact="If those conditions hold, a cross-site request could change the victim's password.",
    )

    result = gate_primary_claims(
        [claim],
        {"subject.php": "if ($_POST['step'] == '2') { update_password($_POST['password_new']); }"},
    )

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()


def test_csrf_claim_without_a_local_request_to_mutation_flow_is_not_published() -> None:
    claim = _finding(
        cwe=352,
        path="subject.php",
        line=2,
        title="Possible CSRF in an external password-change route",
        data_flow="The unseen router may pass a request to a password update.",
        preconditions=(
            "The application must use ambient browser credentials and lack CSRF protection in unseen routing or "
            "middleware. Those framework-level conditions are not provided."
        ),
        impact="If those conditions hold, a cross-site request could change the victim's password.",
    )

    result = gate_primary_claims(
        [claim],
        {"subject.php": "<?php render_password_form(); ?>"},
    )

    assert result.admitted == ()
    assert result.rejected[0].reason_code == "cwe_352_depends_on_unavailable_external_request_control"


def test_source_proven_csrf_failure_is_preserved_without_missing_external_boundary() -> None:
    claim = _finding(
        cwe="CWE-352",
        path="transfer.php",
        line=4,
        title="State-changing GET endpoint has no request-forgery control",
        data_flow="authenticated GET amount -> transfer",
        preconditions="The victim is authenticated with an ambient session cookie.",
        impact="A cross-site image request can trigger the transfer.",
    )

    result = gate_primary_claims(
        [claim],
        {
            "transfer.php": (
                "session_start();\n$user = current_user();\n$amount = $_GET['amount'];\ntransfer($user, $amount);"
            )
        },
    )

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()


def test_unseen_middleware_wording_does_not_hide_an_unrelated_claim() -> None:
    claim = _finding(
        cwe=79,
        path="page.php",
        line=2,
        data_flow="query q -> HTML response",
        preconditions="Routing middleware was not supplied, but q is directly rendered by this handler.",
        impact="Markup executes in the victim's browser.",
    )

    result = gate_primary_claims([claim], {"page.php": "$q = $_GET['q'];\necho $q;"})

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()


def test_remote_body_xss_is_folded_into_ssrf_causal_root() -> None:
    ssrf = _finding(
        title="User-controlled URL reaches HTTP client",
        cwe=918,
        severity="HIGH",
        line=3,
        evidence_excerpt="new HttpGet(url)",
        data_flow="request url -> HttpGet",
        impact="Server-side request forgery.",
    )
    downstream_xss = _finding(
        title="Remote response body is returned without encoding",
        cwe=79,
        severity="MEDIUM",
        line=5,
        evidence_excerpt="writer.write(body)",
        data_flow="fetched remote response body -> response writer",
        impact="Remote content executes in the browser.",
    )
    source = """
String url = request.getParameter("url");
HttpResponse remote = client.execute(new HttpGet(url));
String body = EntityUtils.toString(remote.getEntity());
response.getWriter().write(body);
"""

    result = gate_primary_claims([ssrf, downstream_xss], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.rejected == ()
    assert result.folded[0].claim_index == 1
    assert result.folded[0].folded_into_index == 0
    assert result.folded[0].reason_code == "downstream_xss_folded_into_ssrf_root"


def test_node_http_callback_body_xss_is_folded_into_ssrf_root() -> None:
    ssrf = _finding(
        title="Unvalidated URL reaches Needle",
        cwe=918,
        severity="HIGH",
        path="subject.js",
        line=3,
        data_flow="req.query.url -> needle.get",
    )
    downstream_xss = _finding(
        title="Fetched remote response body is returned as HTML",
        cwe=79,
        severity="MEDIUM",
        path="subject.js",
        line=4,
        data_flow="remote response body -> res.write",
    )
    source = """
const url = req.query.url + req.query.symbol;
needle.get(url, (error, remoteResponse, body) => {
    res.write(body);
});
"""

    result = gate_primary_claims([ssrf, downstream_xss], {"subject.js": source})

    assert [item.claim_index for item in result.admitted] == [0]
    assert result.folded[0].claim_index == 1
    assert result.folded[0].folded_into_index == 0


def test_independent_xss_is_preserved_even_when_file_also_contains_ssrf() -> None:
    ssrf = _finding(cwe=918, severity="HIGH", data_flow="url parameter -> HttpGet")
    independent_xss = _finding(
        cwe=79,
        severity="MEDIUM",
        line=7,
        data_flow="query parameter q -> response writer",
        evidence_excerpt="writer.write(q)",
        impact=(
            "Attacker-controlled query markup executes in the browser; separate remote response logic exists earlier."
        ),
    )
    source = """
String url = request.getParameter("url");
HttpResponse remote = client.execute(new HttpGet(url));
String body = EntityUtils.toString(remote.getEntity());
response.getWriter().write(body);
String q = request.getParameter("q");
response.getWriter().write(q);
"""

    result = gate_primary_claims([ssrf, independent_xss], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0, 1]
    assert result.folded == ()
    assert result.rejected == ()


def test_cwe248_material_proof_is_claim_bound_and_ignores_non_code() -> None:
    process_claim = _finding(
        line=7,
        impact="Malformed input terminates the process and causes persistent denial of service.",
    )
    source = "\n".join(
        (
            "class App {",
            "  void unrelated() { System.exit(1); }",
            '  String bait = "response.write(error.getMessage());";',
            "  // System.exit(1);",
            "  void handle(String input) {",
            "    parse(input);",
            "    throw new IllegalArgumentException(input);",
            "  }",
            "}",
        )
    )

    result = gate_primary_claims([process_claim], {"src/App.java": source})

    assert result.admitted == ()
    assert result.rejected[0].reason_code == "cwe_248_lacks_material_scope_or_leakage"


def test_cwe248_source_effect_does_not_invent_an_unclaimed_impact() -> None:
    per_request_claim = _finding(line=2, impact="Only the malformed request fails.")
    source = "void handle(String input) {\n  System.exit(1);\n}"

    result = gate_primary_claims([per_request_claim], {"src/App.java": source})

    assert result.admitted == ()
    assert [item.claim_index for item in result.rejected] == [0]


def test_remote_body_narrative_does_not_fold_a_different_sink_symbol() -> None:
    ssrf = _finding(cwe=918, severity="HIGH", line=2, data_flow="url -> HttpGet")
    xss = _finding(
        cwe=79,
        severity="MEDIUM",
        line=6,
        evidence_excerpt="writer.write(q)",
        data_flow="q -> response writer; separate remote response body is also handled",
    )
    source = "\n".join(
        (
            'String url = request.getParameter("url");',
            "HttpResponse remote = client.execute(new HttpGet(url));",
            "String body = EntityUtils.toString(remote.getEntity());",
            "response.getWriter().write(body);",
            'String q = request.getParameter("q");',
            "response.getWriter().write(q);",
        )
    )

    result = gate_primary_claims([ssrf, xss], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0, 1]
    assert result.folded == ()


def test_remote_body_flow_must_land_on_the_claimed_sink_line() -> None:
    ssrf = _finding(cwe=918, severity="HIGH", line=2, data_flow="url -> HttpGet")
    xss = _finding(
        cwe=79,
        severity="MEDIUM",
        line=5,
        evidence_excerpt="writer.write(body)",
        data_flow="remote response body -> response writer",
    )
    source = "\n".join(
        (
            'String url = request.getParameter("url");',
            "HttpResponse remote = client.execute(new HttpGet(url));",
            "String body = EntityUtils.toString(remote.getEntity());",
            "response.getWriter().write(body);",
            "audit(body);",
        )
    )

    result = gate_primary_claims([ssrf, xss], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0, 1]
    assert result.folded == ()


def test_remote_body_definition_in_comment_or_other_method_cannot_fold_xss() -> None:
    ssrf = _finding(cwe=918, severity="HIGH", line=2, data_flow="url -> HttpGet")
    xss = _finding(
        cwe=79,
        severity="MEDIUM",
        line=7,
        evidence_excerpt="writer.write(body)",
        data_flow="remote response body -> response writer",
    )
    source = "\n".join(
        (
            "class App {",
            "  String fetch(String url) { return client.execute(new HttpGet(url)).getEntity(); }",
            "  // String body = EntityUtils.toString(remote.getEntity());",
            "  void render(String body) {",
            '    String bait = "EntityUtils.toString(remote.getEntity())";',
            "    validate(body);",
            "    response.getWriter().write(body);",
            "  }",
            "}",
        )
    )

    result = gate_primary_claims([ssrf, xss], {"src/App.java": source})

    assert [item.claim_index for item in result.admitted] == [0, 1]
    assert result.folded == ()


def test_remote_body_from_a_different_fetch_is_not_folded_into_ssrf() -> None:
    ssrf = _finding(
        title="User URL reaches Needle",
        cwe=918,
        severity="HIGH",
        path="app.js",
        line=1,
        evidence_excerpt="needle.get(req.query.url)",
        data_flow="req.query.url -> needle.get",
    )
    xss = _finding(
        cwe=79,
        severity="MEDIUM",
        path="app.js",
        line=4,
        evidence_excerpt="res.write(body)",
        data_flow="fetched remote response body -> res.write",
    )
    source = "\n".join(
        (
            "function ssrf(req) { needle.get(req.query.url, () => {}); }",
            "function renderTrusted() {",
            "  needle.get(TRUSTED_URL, (error, upstream, body) => {",
            "    res.write(body);",
            "  });",
            "}",
        )
    )

    result = gate_primary_claims([ssrf, xss], {"app.js": source})

    assert [item.claim_index for item in result.admitted] == [0, 1]
    assert result.folded == ()


def test_projection_applies_gate_but_keeps_raw_answer_and_explicit_metadata(tmp_path: Path) -> None:
    source = b"void handle(String input) { throw new IllegalArgumentException(input); }"
    target = tmp_path / "src" / "App.java"
    target.parent.mkdir(parents=True)
    target.write_bytes(source)
    artifact = InputArtifact(
        artifact_id="artifact-source",
        original_name="App.java",
        relative_path="src/App.java",
        sha256=hashlib.sha256(source).hexdigest(),
        size_bytes=len(source),
        media_type="text/x-java",
    )
    answer = UniversalPrimaryAnswer(task_id="task", status="completed", findings=[_finding()])
    gate = gate_primary_claims(answer.findings, {"src/App.java": source.decode()})
    raw_before = answer.model_dump_json()
    contract = CanonicalAnalysisContract(
        task_id="task",
        objective="Audit source",
        scenario="code_audit",
        analysis_profile="source_code_security",
        target_scope=["."],
        constraints=[],
        expected_outputs=["findings"],
        autonomy_policy="automatic",
        inputs=[
            {
                "path": "src/App.java",
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
                "media_type": artifact.media_type,
            }
        ],
        viewed_paths=["src/App.java"],
        omitted_paths=[],
        context_sha256="a" * 64,
    )
    meta = ModelCallMeta(
        model_id="mock-5.4",
        prompt_version=CANONICAL_PRIMARY_PROMPT_VERSION,
        response_sha256="b" * 64,
        duration_ms=1,
        used_fallback=False,
        usage=ModelUsage(provider_requests=1),
    )

    projection = project_canonical_result(CanonicalPrimaryResult(answer, meta, contract, gate), [artifact])

    assert answer.model_dump_json() == raw_before
    assert projection.findings == ()
    metadata = projection.coverage["primary_claim_precision_gate"]
    assert metadata["admitted"] == []
    assert metadata["rejected"][0]["claim_index"] == 0
    assert metadata["folded"] == []
    assert projection.coverage["negative_coverage_complete"] is False

    admitted = _finding(
        title="SQL injection",
        cwe=89,
        severity="HIGH",
        line=1,
        evidence_excerpt="statement.execute(input)",
        data_flow="request input -> SQL execution",
        impact="Database compromise.",
    )
    mixed_answer = UniversalPrimaryAnswer(task_id="task", status="completed", findings=[admitted, _finding(line=1)])
    mixed_gate = gate_primary_claims(mixed_answer.findings, {"src/App.java": source.decode()})
    mixed_projection = project_canonical_result(
        CanonicalPrimaryResult(mixed_answer, meta, contract, mixed_gate),
        [artifact],
    )

    assert [item.rule_id for item in mixed_projection.findings] == ["CWE-89"]
    assert mixed_projection.coverage["negative_coverage_complete"] is False


def test_claim_gate_does_not_inject_narrow_heuristics_into_system_prompt() -> None:
    prompt = canonical_system_prompt("source_code_security")

    assert CANONICAL_PRIMARY_PROMPT_VERSION == "secmind-canonical-primary-v8-v084-recall-balanced"
    assert "MD5 or SHA-1 only when" not in prompt
    assert "causal chain as one root finding" not in prompt
    assert "confined to one request is not a vulnerability by itself" not in prompt
