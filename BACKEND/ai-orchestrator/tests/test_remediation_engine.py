from engine.remediation_engine import RemediationEngine


def test_preview_and_execute_respects_auto_remediation_default() -> None:
    engine = RemediationEngine(audit_log_path="/tmp/remediation_audit_test.log")

    finding = {
        "id": "f-1",
        "finding_type": "smb_v1_enabled",
        "details": {"target": "10.0.0.2"},
    }

    preview = engine.preview_for_finding(finding)
    assert preview.finding_type == "smb_v1_enabled"
    assert preview.requires_approval is True

    execution = engine.execute_for_finding(finding, os_name="linux", force=False, auto_remediation_enabled=False)
    assert execution.executed is False
    assert execution.queued is True
