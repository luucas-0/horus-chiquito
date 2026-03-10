"""Remediation planner/executor with explicit preview mode."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping


REMEDIATION_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "smb_v1_enabled": {
        "auto_fix": False,
        "commands": {
            "linux": "sudo smbcontrol smbd debug-suggest",
            "windows": "Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "macos": "sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server EnabledProtocols -int 0",
        },
        "validation": "nmap -p 445 --script smb-protocols {ip}",
    },
    "telnet_open": {
        "auto_fix": True,
        "commands": {
            "linux": "sudo systemctl disable telnet && sudo systemctl stop telnet",
        },
        "validation": "nmap -p 23 {ip}",
    },
    "open_critical_ports": {
        "auto_fix": True,
        "commands": {
            "linux": "sudo iptables -I INPUT -p tcp -m multiport --dports 21,23,445 -j DROP",
        },
        "actions": ["close_critical_ports", "apply_firewall_policy", "revalidate_surface"],
        "validation": "nmap -p 21,23,445 {ip}",
    },
    "weak_credentials": {
        "auto_fix": True,
        "commands": {
            "linux": "sudo sh -lc 'for user in admin user; do pw=$(openssl rand -base64 18 | tr -dc A-Za-z0-9 | head -c 14); echo \"$user:$pw\" | chpasswd; done'",
        },
        "actions": ["rotate_compromised_credentials", "enforce_password_policy", "enable_bruteforce_lockout"],
        "validation": "hydra -l admin -P /tools/passwords.txt {ip} ftp -t 2 -f -I",
    },
    "rdp_no_nla": {
        "auto_fix": False,
        "commands": {
            "windows": "Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
        },
        "validation": "Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'",
    },
    "mass_encryption_detected": {
        "auto_fix": True,
        "actions": ["kill_process", "quarantine_binary", "create_apfs_snapshot", "alert_critical"],
    },
    "honeypot_touched": {
        "auto_fix": True,
        "actions": ["kill_process", "block_process_hash", "alert_critical"],
    },
}

LAB_ENFORCEMENT_SCRIPTS: dict[str, str] = {
    "open_critical_ports": """
set -eu
pkill -x vsftpd >/dev/null 2>&1 || true
pkill -x smbd >/dev/null 2>&1 || true
pkill -x nmbd >/dev/null 2>&1 || true
pkill -x inetd >/dev/null 2>&1 || true
pkill -x in.telnetd >/dev/null 2>&1 || true
pkill -x telnetd >/dev/null 2>&1 || true
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
  pkill -HUP sshd >/dev/null 2>&1 || true
fi
""",
    "weak_credentials": """
set -eu
stamp="$(date +%s)"
admin_pw="HorusAdmin${stamp}"
user_pw="HorusUser${stamp}"
echo "admin:${admin_pw}" | chpasswd
echo "user:${user_pw}" | chpasswd
(printf '%s\n%s\n' "${admin_pw}" "${admin_pw}" | smbpasswd -s admin >/dev/null) || true
(printf '%s\n%s\n' "${user_pw}" "${user_pw}" | smbpasswd -s user >/dev/null) || true
mkdir -p /srv/backups
{
  echo "rotated_at=${stamp}"
  echo "admin=${admin_pw}"
  echo "user=${user_pw}"
} > /srv/backups/.horus_rotated_credentials.txt
chmod 600 /srv/backups/.horus_rotated_credentials.txt || true
""",
    "telnet_open": """
set -eu
if [ -f /etc/inetd.conf ]; then
  sed -i 's/^telnet /# telnet /' /etc/inetd.conf || true
fi
pkill -x in.telnetd >/dev/null 2>&1 || true
pkill -x telnetd >/dev/null 2>&1 || true
pkill -x inetd >/dev/null 2>&1 || true
""",
    "smb_v1_enabled": """
set -eu
if [ -f /etc/samba/smb.conf ]; then
  sed -i 's/^[[:space:]]*server min protocol.*/  server min protocol = SMB3/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*client min protocol.*/  client min protocol = SMB3/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*lanman auth.*/  lanman auth = no/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*ntlm auth.*/  ntlm auth = no/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*map to guest.*/  map to guest = Never/' /etc/samba/smb.conf || true
  sed -i 's/^[[:space:]]*guest ok.*/  guest ok = no/' /etc/samba/smb.conf || true
  pkill -HUP smbd >/dev/null 2>&1 || true
fi
""",
}


@dataclass(frozen=True)
class RemediationPreview:
    """Dry-run preview returned by remediation preview endpoint."""

    finding_id: str
    finding_type: str
    auto_fix: bool
    commands: dict[str, str] = field(default_factory=dict)
    actions: list[str] = field(default_factory=list)
    validation: str | None = None
    requires_approval: bool = True


@dataclass(frozen=True)
class RemediationExecution:
    """Result of remediation execution or queue operation."""

    finding_id: str
    executed: bool
    queued: bool
    message: str
    commands: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LabEnforcementResult:
    """Result of optional lab-only host enforcement."""

    attempted: bool
    success: bool
    note: str


class RemediationEngine:
    """Preview and execute remediation with audit logging."""

    def __init__(self, audit_log_path: str | None = None) -> None:
        self.auto_remediation_default = os.getenv("AUTO_REMEDIATION", "false").lower() == "true"
        self.enforcement_enabled = os.getenv("REMEDIATION_ENFORCEMENT", "false").lower() == "true"
        self.enforcement_timeout_sec = self._parse_positive_int(
            os.getenv("REMEDIATION_ENFORCEMENT_TIMEOUT_SEC", "25"),
            fallback=25,
        )
        self.allowed_targets = self._parse_target_set(
            os.getenv("REMEDIATION_ALLOWED_TARGETS", "172.28.10.20")
        )
        self.target_container_map = self._parse_target_container_map(
            os.getenv("REMEDIATION_TARGET_CONTAINER_MAP", "172.28.10.20=lab-vuln-host-clone")
        )
        self.audit_log_path = Path(audit_log_path) if audit_log_path else Path(__file__).resolve().with_name("remediation_audit.log")
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    def preview_for_finding(self, finding: Mapping[str, Any]) -> RemediationPreview:
        """Build remediation preview for one finding."""

        finding_type = str(finding.get("finding_type", ""))
        finding_id = str(finding.get("id", ""))
        playbook = REMEDIATION_PLAYBOOKS.get(finding_type)

        if playbook is None:
            return RemediationPreview(
                finding_id=finding_id,
                finding_type=finding_type,
                auto_fix=False,
                commands={},
                actions=[],
                validation=None,
                requires_approval=True,
            )

        return RemediationPreview(
            finding_id=finding_id,
            finding_type=finding_type,
            auto_fix=bool(playbook.get("auto_fix", False)),
            commands=dict(playbook.get("commands", {})),
            actions=list(playbook.get("actions", [])),
            validation=playbook.get("validation"),
            requires_approval=not bool(playbook.get("auto_fix", False)),
        )

    def execute_for_finding(
        self,
        finding: Mapping[str, Any],
        *,
        os_name: str,
        force: bool = False,
        auto_remediation_enabled: bool | None = None,
    ) -> RemediationExecution:
        """Execute or queue remediation action.

        Notes:
            - All executions are audited.
            - Commands are not blindly executed when approval is required.
        """

        preview = self.preview_for_finding(finding)
        enabled = self.auto_remediation_default if auto_remediation_enabled is None else auto_remediation_enabled

        if not preview.commands and not preview.actions:
            execution = RemediationExecution(
                finding_id=preview.finding_id,
                executed=False,
                queued=False,
                message="No remediation playbook defined for finding.",
            )
            self._audit("no_playbook", finding=finding, execution=execution)
            return execution

        if not enabled and not force:
            execution = RemediationExecution(
                finding_id=preview.finding_id,
                executed=False,
                queued=True,
                message="AUTO_REMEDIATION is disabled. Remediation queued for manual approval.",
                commands=[preview.commands.get(os_name, "")] if preview.commands else [],
                actions=preview.actions,
            )
            self._audit("queued_auto_remediation_disabled", finding=finding, execution=execution)
            return execution

        if preview.requires_approval and not force:
            execution = RemediationExecution(
                finding_id=preview.finding_id,
                executed=False,
                queued=True,
                message="Playbook requires explicit human approval.",
                commands=[preview.commands.get(os_name, "")] if preview.commands else [],
                actions=preview.actions,
            )
            self._audit("queued_requires_approval", finding=finding, execution=execution)
            return execution

        selected_command = preview.commands.get(os_name)
        commands = [selected_command] if selected_command else []

        enforcement = self._execute_lab_enforcement(finding=finding, finding_type=preview.finding_type)
        audit_action = "executed"
        executed = True
        message = "Remediation executed in controlled mode."

        if enforcement.attempted and enforcement.success:
            audit_action = "executed_lab_enforced"
            message = "Remediation executed and enforced in lab mode. " + enforcement.note
        elif enforcement.attempted and not enforcement.success:
            audit_action = "executed_lab_failed"
            executed = False
            message = "Remediation planned but lab enforcement failed. " + enforcement.note
        elif self.enforcement_enabled:
            message = message + " " + enforcement.note

        execution = RemediationExecution(
            finding_id=preview.finding_id,
            executed=executed,
            queued=False,
            message=message,
            commands=commands,
            actions=preview.actions,
        )
        self._audit(audit_action, finding=finding, execution=execution)
        return execution

    def _execute_lab_enforcement(
        self,
        *,
        finding: Mapping[str, Any],
        finding_type: str,
    ) -> LabEnforcementResult:
        if not self.enforcement_enabled:
            return LabEnforcementResult(attempted=False, success=False, note="Lab enforcement disabled.")

        script = LAB_ENFORCEMENT_SCRIPTS.get(finding_type)
        if not script:
            return LabEnforcementResult(attempted=False, success=False, note="No lab enforcement handler for this finding type.")

        target = self._extract_target(finding)
        if not target:
            return LabEnforcementResult(attempted=False, success=False, note="Finding target is missing; no lab command executed.")

        if self.allowed_targets and target not in self.allowed_targets:
            return LabEnforcementResult(
                attempted=False,
                success=False,
                note=f"Target {target} is outside REMEDIATION_ALLOWED_TARGETS.",
            )

        container = self.target_container_map.get(target)
        if not container:
            return LabEnforcementResult(
                attempted=False,
                success=False,
                note=f"No container mapping found for target {target}.",
            )

        ok, detail = self._run_docker_exec(container=container, shell_script=script)
        if ok:
            return LabEnforcementResult(
                attempted=True,
                success=True,
                note=f"Applied on {container} ({target}).",
            )

        return LabEnforcementResult(
            attempted=True,
            success=False,
            note=f"Container {container} ({target}) error: {detail}",
        )

    def _run_docker_exec(self, *, container: str, shell_script: str) -> tuple[bool, str]:
        command = ["docker", "exec", container, "sh", "-lc", shell_script]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.enforcement_timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {self.enforcement_timeout_sec}s"
        except FileNotFoundError:
            return False, "docker binary not found"
        except Exception as error:  # pragma: no cover - defensive path
            return False, str(error)

        if completed.returncode == 0:
            return True, "ok"

        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        detail = stderr or stdout or f"exit code {completed.returncode}"
        return False, detail

    def _extract_target(self, finding: Mapping[str, Any]) -> str:
        details = finding.get("details") if isinstance(finding.get("details"), Mapping) else {}
        raw_target = details.get("target") if isinstance(details, Mapping) else None
        if not raw_target:
            raw_target = finding.get("target")
        return str(raw_target or "").strip()

    def _parse_positive_int(self, raw_value: str, *, fallback: int) -> int:
        try:
            parsed = int(str(raw_value).strip())
        except Exception:
            return fallback
        if parsed <= 0:
            return fallback
        return parsed

    def _parse_target_set(self, raw_value: str) -> set[str]:
        values = {
            item.strip()
            for item in str(raw_value or "").split(",")
            if item.strip()
        }
        return values

    def _parse_target_container_map(self, raw_value: str) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for chunk in str(raw_value or "").split(","):
            part = chunk.strip()
            if not part or "=" not in part:
                continue
            target, container = part.split("=", maxsplit=1)
            target = target.strip()
            container = container.strip()
            if target and container:
                mapping[target] = container
        return mapping

    def _audit(self, action: str, *, finding: Mapping[str, Any], execution: RemediationExecution) -> None:
        """Write immutable JSON audit logs for every remediation decision."""

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "finding": dict(finding),
            "execution": {
                "finding_id": execution.finding_id,
                "executed": execution.executed,
                "queued": execution.queued,
                "message": execution.message,
                "commands": execution.commands,
                "actions": execution.actions,
            },
        }

        with self.audit_log_path.open("a", encoding="utf-8") as file_handle:
            file_handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
