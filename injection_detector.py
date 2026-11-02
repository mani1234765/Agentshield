from ast import pattern
import re
import unicodedata
from dataclasses import asdict, dataclass

MAX_INPUT_LENGTH = 100_000

RULES = {
    "instruction_override": (
        35,
        [
            r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions|rules|prompts)\b",
            r"\b(?:forget|override)\s+(?:all\s+)?(?:your\s+)?(?:instructions|rules|policies)\b",
            r"\b(?:stop|do\s+not)\s+following\s+(?:your|the)\s+(?:rules|instructions)\b",
            r"\b(?:new|updated)\s+(?:system\s+)?instructions?\s*:",
            r"\bthis\s+(?:prompt|instruction)\s+(?:overrides|supersedes)\b",
        ],
    ),
    "secret_extraction": (
        50,
        [
            r"\b(?:reveal|print|show|expose|leak)\s+(?:your\s+|the\s+)?(?:system\s+prompt|developer\s+instructions|secrets?|api\s+keys?|credentials?)\b",
            r"\b(?:dump|extract|retrieve)\s+(?:all\s+)?(?:environment\s+variables|credentials|secrets)\b",
            r"\b(?:send|upload|transfer)\s+.{0,80}\b(?:api\s+key|password|secret|token|credential)\b",
            r"\b(?:read|open|print)\s+.{0,80}(?:\.env\b|credentials\.json\b|id_rsa\b)",
        ],
    ),
    "security_bypass": (
        45,
        [
            r"\b(?:disable|turn\s+off|bypass)\s+(?:the\s+)?(?:security|safety|logging|monitoring|authentication|authorization)\b",
            r"\bskip\s+(?:the\s+)?(?:permission|approval|authorization)\s+(?:check|step|process)\b",
            r"\b(?:remove|disable)\s+(?:all\s+)?(?:restrictions|guardrails|safeguards)\b",
            r"\bgrant\s+(?:yourself|me)\s+(?:admin|root|full)\s+(?:access|permissions)\b",
            r"\b(?:mark|set)\s+.{0,40}\b(?:approved|allowed)\s*(?:=|to|as)\s*true\b",
        ],
    ),
    "role_spoofing": (
        40,
        [
            r"(?:^|\n)\s*\[\s*(?:system|developer|administrator)\s*\]",
            r"(?:^|\n)\s*<\s*(?:system|developer|administrator)\s*>",
            r"(?:^|\n)\s*#{1,3}\s*(?:system|developer|administrator)\s+(?:message|instructions|prompt)\b",
            r"\b(?:system|developer|administrator)\s+(?:message|instruction)\s*:",
            r"\b(?:enter|activate)\s+(?:developer|admin|unrestricted)\s+mode\b",
            r"\b(?:i\s+am|this\s+is)\s+(?:your\s+)?(?:developer|administrator|system\s+owner)\b",
        ],
    ),
    "tool_misuse": (
        45,
        [
            r"\b(?:delete|remove|erase)\s+(?:all\s+)?(?:files|logs|records|databases)\b",
            r"\b(?:change|modify|rewrite)\s+(?:the\s+)?(?:security\s+policy|permissions|audit\s+logs)\b",
            r"\b(?:disable|stop|kill)\s+(?:the\s+)?(?:audit|monitoring|security)\s+(?:service|process)\b",
            r"\b(?:execute|invoke|run)\s+.{0,80}\bwithout\s+(?:permission|approval)\b",
        ],
    ),
    "authority_spoofing": (
        40,
        [
            r"\b(?:openai|anthropic|the\s+developer)\s+(?:has\s+)?(?:authorized|approved|instructed)\b",
            r"\b(?:highest|top)\s+priority\s+(?:instruction|message|command)\b",
            r"\b(?:official|trusted)\s+(?:system|developer|admin)\s+(?:instruction|message)\b",
            r"\b(?:security|policy)\s+(?:has\s+been|is\s+now)\s+(?:disabled|overridden)\b",
        ],
    ),
    "output_manipulation": (
        25,
        [
            r"\b(?:do\s+not|don't)\s+(?:mention|report|log|record)\s+(?:this|the)\s+(?:action|request|operation)\b",
            r"\b(?:hide|conceal|suppress)\s+(?:this|the)\s+(?:action|request|operation)\b",
            r"\b(?:falsify|fabricate|alter)\s+(?:the\s+)?(?:audit|security|execution)\s+(?:logs|results)\b",
        ],
    ),
}

COMPILED_RULES = {
    category: (
        weight,
        [re.compile(pattern, re.IGNORECASE) for pattern in patterns],
    )
    for category, (weight, patterns) in RULES.items()
}

@dataclass
class DetectionResult:
    detected: bool
    risk_score: int
    risk_level: str
    action: str
    categories: list[str]
    matched_rules: list[str]
    reason: str

def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)

    for char in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        text = text.replace(char, "")

    text = re.sub(r"[^\S\n]+", " ", text)

    return text

def is_negated_instruction_override(text: str, match: re.Match) -> bool:
    prefix = text[max(0, match.start() - 100):match.start()]

    return bool(
        re.search(
            r"\b(?:should|must|do)\s+not\s+$",
            prefix,
            re.IGNORECASE,
        )
    )

def detect_injection(text: str) -> dict:
    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    if len(text) > MAX_INPUT_LENGTH:
        return asdict(DetectionResult(
            detected=True,
            risk_score=100,
            risk_level="high",
            action="block",
            categories=["input_limit"],
            matched_rules=[],
            reason="Input exceeds the detector's inspection limit",
        ))

    normalized = normalize_text(text)

    categories = []
    matched_rules = []
    score = 0

    for category, (weight, patterns) in COMPILED_RULES.items():
        category_matches = []

        for pattern in patterns:
            for match in pattern.finditer(normalized):
                if (
                    category == "instruction_override"
                    and is_negated_instruction_override(normalized, match)
                ):
                    continue
                category_matches.append(pattern.pattern)
                break

        # IMPORTANT: This must be outside the inner loop.
        if category_matches:
            categories.append(category)
            matched_rules.extend(category_matches)
            score += weight

    score = min(score, 100)

    if score >= 70:
        level = "high"
        action = "block"
    elif score >= 25:
        level = "medium"
        action = "review"
    else:
        level = "low"
        action = "allow"

    return asdict(DetectionResult(
        detected=bool(categories),
        risk_score=score,
        risk_level=level,
        action=action,
        categories=categories,
        matched_rules=matched_rules,
        reason=(
            "Suspicious instruction patterns detected"
            if categories
            else "No matching injection patterns"
        ),
    ))
