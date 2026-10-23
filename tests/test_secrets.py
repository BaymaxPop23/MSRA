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
