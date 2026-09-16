from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class MockLLMProvider:
    """Deterministic offline provider used when no API key is configured.

    It derives a structured decision from the evidence and signals assembled by
    the reasoning engine, without any network access.
    """

    name = "mock"

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        input_data: dict[str, Any],
        response_model: type[T],
    ) -> T:
        decision = self._derive(input_data)
        return response_model.model_validate(decision)

    def _derive(self, input_data: dict[str, Any]) -> dict[str, Any]:
        evidence = input_data.get("evidence", [])
        observations = input_data.get("observations", [])
        signals = input_data.get("signals", {})
        evidence_ids = [e["id"] for e in evidence]
        asset_critical = bool(signals.get("asset_critical"))
        malicious_indicator = bool(signals.get("malicious_indicator"))
        rapid_repeat = int(signals.get("rapid_repeat_count", 0))
        degraded = bool(signals.get("degraded"))
        benign_indicator = bool(signals.get("benign_indicator"))
        missing_asset = bool(signals.get("missing_asset"))
        has_mitre = bool(signals.get("has_mitre"))

        if malicious_indicator and (asset_critical or rapid_repeat >= 3):
            classification = "true_positive"
            severity = "critical" if asset_critical and malicious_indicator else "high"
            confidence = 0.88
            escalation = True
        elif malicious_indicator:
            classification = "true_positive"
            severity = "high"
            confidence = 0.82
            escalation = True
        elif benign_indicator and not malicious_indicator:
            classification = "false_positive" if rapid_repeat == 0 else "benign"
            severity = "low"
            confidence = 0.7
            escalation = False
        elif has_mitre and not malicious_indicator:
            classification = "needs_investigation"
            severity = "medium"
            confidence = 0.55
            escalation = False
        else:
            classification = "needs_investigation"
            severity = "medium"
            confidence = 0.5
            escalation = False

        if benign_indicator and malicious_indicator:
            classification = "needs_investigation"
            confidence = 0.45
            escalation = True

        summary = self._summary(
            classification, severity, malicious_indicator, asset_critical, rapid_repeat
        )
        actions = self._actions(classification, escalation, asset_critical)
        uncertainties: list[str] = []
        if missing_asset:
            uncertainties.append("Asset inventory did not contain the affected host.")
        if degraded:
            uncertainties.append("One or more enrichment tools failed; context is degraded.")
        if not malicious_indicator and classification == "needs_investigation":
            uncertainties.append("No definitive malicious indicator was observed.")

        return {
            "classification": classification,
            "severity": severity,
            "confidence": confidence,
            "evidence_ids": evidence_ids,
            "observations": observations,
            "inferences": self._inferences(malicious_indicator, asset_critical, rapid_repeat),
            "reasoning_summary": summary,
            "recommended_actions": actions,
            "escalation_required": escalation,
            "uncertainties": uncertainties,
        }

    @staticmethod
    def _inferences(malicious: bool, asset_critical: bool, rapid: int) -> list[str]:
        out: list[str] = []
        if malicious and asset_critical:
            out.append(
                "A malicious indicator linked to a critical asset materially raises risk."
            )
        if rapid >= 3:
            out.append("Repeated activity within the correlation window suggests intent.")
        if not malicious:
            out.append("Absence of malicious reputation lowers likelihood of compromise.")
        return out

    @staticmethod
    def _summary(
        classification: str,
        severity: str,
        malicious: bool,
        asset_critical: bool,
        rapid: int,
    ) -> str:
        if classification == "true_positive":
            return (
                f"Observed activity is consistent with a true positive at {severity} "
                f"severity. Malicious indicator present: {malicious}. "
                f"Critical asset involved: {asset_critical}. Related recent alerts: {rapid}."
            )
        if classification in {"false_positive", "benign"}:
            return (
                "Available evidence indicates benign or expected activity with no "
                "confirmed malicious indicator."
            )
        return (
            "Evidence is inconclusive; the alert requires analyst investigation before "
            "a final determination."
        )

    @staticmethod
    def _actions(
        classification: str, escalation: bool, asset_critical: bool
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        if classification == "true_positive":
            actions.append(
                {
                    "action": "Investigate the endpoint and network connection",
                    "rationale": "Confirm whether malicious execution occurred.",
                    "priority": 1,
                    "requires_human_approval": True,
                }
            )
            actions.append(
                {
                    "action": "Search for additional activity from the indicator",
                    "rationale": "Determine blast radius across the estate.",
                    "priority": 2,
                    "requires_human_approval": True,
                }
            )
            if escalation or asset_critical:
                actions.append(
                    {
                        "action": "Escalate to incident response",
                        "rationale": "Critical asset and malicious indicator combination.",
                        "priority": 1,
                        "requires_human_approval": True,
                    }
                )
        elif classification in {"false_positive", "benign"}:
            actions.append(
                {
                    "action": "Close as benign after analyst confirmation",
                    "rationale": "Evidence supports expected activity.",
                    "priority": 3,
                    "requires_human_approval": True,
                }
            )
        else:
            actions.append(
                {
                    "action": "Collect additional endpoint telemetry",
                    "rationale": "Insufficient evidence for a determination.",
                    "priority": 2,
                    "requires_human_approval": True,
                }
            )
        return actions
