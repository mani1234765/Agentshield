
from injection_detector import detect_injection


def inspect_document(content: str) -> dict:
    """Inspect untrusted document content."""

    result = detect_injection(content)

    if result["action"] != "allow":
        return {
            "allowed": False,
            "reason": "Potential prompt injection detected",
            "risk_score": result["risk_score"],
            "categories": result["categories"],
        }

    return {
        "allowed": True,
        "reason": "No suspicious patterns detected",
        "risk_score": result["risk_score"],
        "categories": result["categories"],
    }


def protect_document(content: str) -> str:
    """Return safe content or a blocked response."""

    inspection = inspect_document(content)

    if not inspection["allowed"]:
        return "BLOCKED: Potential prompt injection detected"

    return content
