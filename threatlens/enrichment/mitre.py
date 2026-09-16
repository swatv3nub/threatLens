from __future__ import annotations

from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult, ToolStatus
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import MitreTechnique

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059.001": {
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries abuse PowerShell for execution.",
    },
    "T1059.003": {
        "technique_name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries abuse cmd.exe for execution.",
    },
    "T1071.004": {
        "technique_name": "DNS",
        "tactic": "Command and Control",
        "description": "Adversaries use DNS for C2.",
    },
    "T1071.001": {
        "technique_name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries use HTTP(S) for C2.",
    },
    "T1110": {
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries guess credentials via brute force.",
    },
    "T1021": {
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries use remote services for lateral movement.",
    },
    "T1021.002": {
        "technique_name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Adversaries use SMB admin shares to move laterally.",
    },
    "T1204.002": {
        "technique_name": "Malicious File",
        "tactic": "Execution",
        "description": "Adversaries rely on a user to execute a malicious file.",
    },
    "T1105": {
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries transfer tools into the environment.",
    },
    "T1041": {
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries exfiltrate data over the C2 channel.",
    },
    "T1046": {
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries scan for network services.",
    },
}

SUSPICIOUS_POWERSHELL_TOKENS = (
    "-enc",
    "-encodedcommand",
    "-nop",
    "-w hidden",
    "downloadstring",
    "invoke-expression",
    "iex",
    "bypass",
)

SUSPICIOUS_LOLBINS = ("psexesvc", "psexec", "wmic", "rundll32", "regsvr32", "mshta")


class MitreLookupTool(BaseTool):
    name = "mitre_attack"
    reliability = 0.75

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return True

    async def execute(self, context: ToolContext) -> ToolResult:
        alert = context.alert
        mapped: list[MitreTechnique] = []

        def add(tid: str, evidence: str, confidence: float) -> None:
            meta = TECHNIQUES[tid]
            mapped.append(
                MitreTechnique(
                    technique_id=tid,
                    technique_name=meta["technique_name"],
                    tactic=meta["tactic"],
                    description=meta["description"],
                    confidence=confidence,
                    evidence=evidence,
                )
            )

        command = (alert.command_line or "").lower()
        process = (alert.process_name or "").lower()

        if "powershell" in process or "powershell" in command:
            if any(tok in command for tok in SUSPICIOUS_POWERSHELL_TOKENS):
                add("T1059.001", f"powershell command line: {alert.command_line}", 0.9)
            else:
                add("T1059.001", "powershell execution observed", 0.6)
        if "cmd.exe" in process or "cmd /c" in command:
            add("T1059.003", "cmd.exe execution observed", 0.6)
        if any(lol in process for lol in SUSPICIOUS_LOLBINS):
            add("T1021.002", f"lateral tooling process: {alert.process_name}", 0.7)

        if alert.domain and alert.destination_port == 53:
            add("T1071.004", f"DNS query to {alert.domain}", 0.7)
        elif alert.domain or alert.url:
            indicator = alert.domain or alert.url
            add("T1071.001", f"web-based indicator: {indicator}", 0.6)

        if alert.destination_port in (445, 139) or alert.protocol == "smb":
            add("T1021.002", "SMB traffic observed", 0.7)
        elif alert.destination_port in (22, 3389, 5985, 5986):
            add("T1021", f"remote service port {alert.destination_port}", 0.6)

        if alert.file_hash:
            add("T1204.002", f"file hash observed: {alert.file_hash}", 0.5)

        category = (alert.category or "").lower()
        if "brute" in category or "authentication" in category:
            add("T1110", "authentication failure pattern", 0.7)
        if "scan" in category:
            add("T1046", "network scanning behaviour", 0.5)
        if "lateral" in category:
            add("T1021", "lateral movement category", 0.7)
        if alert.url and any(
            ext in alert.url.lower() for ext in (".bin", ".exe", ".dll", ".ps1")
        ):
            add("T1105", f"tool download url: {alert.url}", 0.7)

        deduped: dict[str, MitreTechnique] = {}
        for tech in mapped:
            existing = deduped.get(tech.technique_id)
            if existing is None or tech.confidence > existing.confidence:
                deduped[tech.technique_id] = tech
        results = list(deduped.values())

        if not results:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.success,
                data={"techniques": []},
                summary="no MITRE ATT&CK techniques mapped",
                confidence=0.3,
            )
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.success,
            data={"techniques": [t.model_dump(mode="json") for t in results]},
            summary="mapped: " + ", ".join(t.technique_id for t in results),
            confidence=self.reliability,
        )
