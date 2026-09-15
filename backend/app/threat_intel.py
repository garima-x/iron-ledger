MITRE_TECHNIQUES = [
    {"id": "T0855", "name": "Unauthorized Command Message", "tactic": "Inhibit Response Function"},
    {"id": "T0836", "name": "Modify Parameter", "tactic": "Impair Process Control"},
    {"id": "T0831", "name": "Manipulation of Control", "tactic": "Impair Process Control"},
    {"id": "T0879", "name": "Damage to Property", "tactic": "Impact"},
    {"id": "T0815", "name": "Denial of View", "tactic": "Inhibit Response Function"},
    {"id": "T0888", "name": "Remote System Information Discovery", "tactic": "Discovery"},
]

# Deliberately simplified for a coursework demo — a production attribution
# engine would derive these weights from incident reporting (e.g. Dragos /
# MITRE ICS ATT&CK group profiles) rather than hand-picked numbers.
ACTOR_PROFILES = {
    "Xenotime": {"T0855": 3, "T0831": 3, "T0879": 3, "T0836": 1},
    "Sandworm": {"T0836": 3, "T0815": 2, "T0879": 2},
    "Equation Group": {"T0888": 3, "T0815": 1},
    "Volt Typhoon": {"T0888": 3, "T0836": 1},
}


def score_attribution(mitre_hits: set[str]) -> tuple[dict[str, int], str | None]:
    """Score actors by matched-technique weight, normalized against the
    strongest match (not against each actor's own profile total) — otherwise
    a narrow actor profile trivially hits 100% the moment its few techniques
    appear, even when a better-evidenced actor also matches everything."""
    raw: dict[str, int] = {}
    for actor, weights in ACTOR_PROFILES.items():
        raw[actor] = sum(w for tech, w in weights.items() if tech in mitre_hits)
    peak = max(raw.values(), default=0)
    scores = {actor: (round(val / peak * 100) if peak else 0) for actor, val in raw.items()}
    leader = max(scores, key=scores.get) if peak else None
    return scores, leader
