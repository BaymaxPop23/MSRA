from msra.analysis.secrets import mask, scan_text, shannon_entropy


def _ids(findings):
    return {f.extra["rule_id"] for f in findings}


def test_known_formats_detected_and_masked():
    text = '''
    String aws = "AKIAIOSFODNN7EXAMPLE";
    String g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
    String slack = "xoxb-123456789012-abcdefghijklmn";
    String url = "https://admin:hunter2pass@internal.example.net/x";
    -----BEGIN RSA PRIVATE KEY-----
    '''
    findings = scan_text("A.java", text)
    ids = _ids(findings)
    assert {"secret-aws-access-key", "secret-google-api-key", "secret-slack-token",
            "secret-basic-auth-url", "secret-private-key-block"} <= ids
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence.snippet
        assert "hunter2pass" not in f.evidence.snippet
        assert "hunter2pass" not in f.evidence.matched_text


def test_placeholders_and_identifiers_ignored():
    text = '''
    String password = "changeme_placeholder";
    String api_key = "YOUR_API_KEY_HERE_12345";
    String token = "com.example.app.TOKEN_KEY";
    String apiKeyName = "someApiKeyConstantName";
    '''
    assert scan_text("A.java", text) == []


def test_high_entropy_assignment_flagged():
    text = 'private static final String API_SECRET = "k8Jd9sL2pQx7Vb3NzR5tY1uW6eH4cG0m";'
    findings = scan_text("A.java", text)
    assert any(f.extra["rule_id"] == "secret-high-entropy-literal" for f in findings)


def test_xml_string_resource_flagged():
    text = '<string name="client_secret">q9Zx3Lm7Tb2Vn8Kd5Rw1Yc4Hs6Jf0PaGu</string>'
    assert any(f.extra["rule_id"] == "secret-high-entropy-literal" for f in scan_text("strings.xml", text))


def test_mask_and_entropy():
    assert mask("short") == "*****"
    m = mask("AKIAIOSFODNN7EXAMPLE")
    assert m.startswith("AKIA") and m.endswith("MPLE") and "IOSFODNN" not in m
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("abcdefgh") > 2.9


def test_private_key_block_fully_redacted():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"
    text = f"// config\n-----BEGIN PRIVATE KEY-----\n{body}\n{body}\n-----END PRIVATE KEY-----\n"
    findings = scan_text("k.pem.java", text)
    pem = [f for f in findings if f.extra["rule_id"] == "secret-private-key-block"]
    assert len(pem) == 1
    assert body not in pem[0].evidence.snippet
    assert body[:20] not in pem[0].evidence.snippet


def test_long_tokens_masked_in_any_snippet():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV"
    text = f'String a = "{jwt}";\nString b = "AKIAIOSFODNN7EXAMPLE";\n'
    for f in scan_text("A.java", text):
        assert jwt not in f.evidence.snippet


def test_generic_scan_is_not_quadratic_on_minified_input():
    import time
    blob = ("a" * 200_000) + 'password:"' + ("x" * 50)
    t0 = time.time()
    scan_text("min.js", blob)
    scan_text("min.js", "token" * 40_000)
    assert time.time() - t0 < 3
