from jane_verify.inspection import CodeInspector

def test_inspector_finds_private_key_marker(tmp_path):
    p=tmp_path/'a.py'; p.write_text('x="-----BEGIN PRIVATE KEY-----"\n')
    findings=CodeInspector().scan(tmp_path)
    assert any(f.severity=='high' for f in findings)
