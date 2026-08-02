"""Attack trap implementations based on Franklin et al. (2026) taxonomy."""

TRAP_CATEGORIES = {
    "content_injection": "Exploits gap between human-visible rendering and machine parsing",
    "semantic_manipulation": "Corrupts reasoning via biased framing and contextual priming",
    "cognitive_state": "Poisons RAG knowledge bases and agent memory",
    "behavioral_control": "Embedded jailbreaks and data exfiltration triggers",
    "compositional": "Split payloads across multiple benign-looking sources",
    "exfiltration": "Confused-deputy attacks coercing agents to leak data",
}
