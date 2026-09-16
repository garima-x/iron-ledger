MITRE_TECHNIQUES = [
    {"id": "T0855", "name": "Unauthorized Command Message", "tactic": "Inhibit Response Function"},
    {"id": "T0836", "name": "Modify Parameter", "tactic": "Impair Process Control"},
    {"id": "T0831", "name": "Manipulation of Control", "tactic": "Impair Process Control"},
    {"id": "T0879", "name": "Damage to Property", "tactic": "Impact"},
    {"id": "T0815", "name": "Denial of View", "tactic": "Inhibit Response Function"},
    {"id": "T0888", "name": "Remote System Information Discovery", "tactic": "Discovery"},
]

# ---------------------------------------------------------------------------
# Threat-actor profiles, grounded in public reporting rather than hand-picked
# numbers. Each actor below is a real MITRE ATT&CK for ICS group (or, for
# ALLANITE, a group cross-referenced in MITRE's ICS group knowledge base and
# named by Dragos, who is credited as a contributor on several ICS group
# pages including XENOTIME's). "Equation Group," used in an earlier version
# of this file, was removed: it has no documented ICS-domain technique
# mapping in MITRE ATT&CK — it's an Enterprise-matrix actor (Kaspersky,
# "Equation Group," 2015), and including it here would have been exactly the
# kind of uncited assumption this pass was meant to fix.
#
# Sources per actor:
#
# XENOTIME / TEMP.Veles — MITRE ATT&CK Group G0088
#   https://attack.mitre.org/groups/G0088/
#   Built TRITON (MITRE Software S0609), malware designed specifically to
#   reprogram Schneider Electric Triconex safety-instrumented system
#   controllers at a Saudi petrochemical plant — the only publicly
#   documented case of an attacker directly manipulating a safety system.
#   Mandiant/FireEye, "TRITON Attribution: Russian Government-Owned Lab
#   Most Likely Built Custom Intrusion Tools," Oct 2018. Dragos, "TRISIS
#   Malware: Analysis of Safety System Targeted Malware," 2018.
#
# Sandworm Team — MITRE ATT&CK Group G0034 (aka ELECTRUM, Voodoo Bear,
#   Seashell Blizzard, APT44)
#   https://attack.mitre.org/groups/G0034/
#   Behind CRASHOVERRIDE/Industroyer, which issued direct unauthorized
#   breaker-open commands to Ukrainian grid substations over IEC 101/104
#   and IEC 61850, and included a component built specifically to disable
#   Siemens SIPROTEC protection relays. Dragos, "CRASHOVERRIDE: Analysis
#   of the Threat to Electric Grid Operations," 2017. US-CERT Alert
#   IR-ALERT-H-16-056-01 (2016 Ukraine grid attack).
#
# Volt Typhoon — MITRE ATT&CK Group G1017 (aka VOLTZITE, Vanguard Panda,
#   Insidious Taurus)
#   https://attack.mitre.org/groups/G1017/
#   Notably different profile: its entire publicly-documented playbook is
#   reconnaissance and long-term "living off the land" persistence —
#   pre-positioning inside US critical infrastructure OT networks for
#   potential future disruption, not actively manipulating processes.
#   CISA/NSA/FBI joint advisory, "PRC State-Sponsored Actors Compromise
#   and Maintain Persistent Access to U.S. Critical Infrastructure," Feb
#   2024. Microsoft, "Volt Typhoon targets US critical infrastructure with
#   living-off-the-land techniques," May 2023.
#
# ALLANITE
#   Targets US/UK electric utilities with tactics similar to Dragonfly
#   2.0/DYMALLOY, but — per MITRE's own ICS group knowledge base — has not
#   exhibited disruptive or destructive capability. Dragos, "Allanite,"
#   n.d., cited at https://collaborate.mitre.org/attackics/index.php/Groups.
#
# Weighting rationale: each actor is scored only on techniques it has
# actually been publicly reported using. Volt Typhoon and ALLANITE are
# deliberately weighted almost entirely toward T0888 (reconnaissance) with
# no weight on the destructive techniques (T0831/T0836/T0879), because that
# reflects their actual documented behavior, not because the scoring model
# assumes reconnaissance-focused actors are less sophisticated. A dataset
# that scripts a SIS-defeat scenario (as this project's demo does) *should*
# score Xenotime highest — that's a real, checkable claim about Xenotime's
# reported TTPs, not an artifact of the weights being tuned to produce that
# answer.
# ---------------------------------------------------------------------------
ACTOR_PROFILES = {
    "Xenotime (TEMP.Veles, G0088)": {
        "T0831": 3,  # TRITON's core function: reprogram SIS controller logic
        "T0879": 3,  # one of the few groups with demonstrated destructive intent/capability
        "T0855": 2,  # sent unauthorized commands to the Triconex controllers
        "T0836": 1,  # modified controller parameters as part of reprogramming
    },
    "Sandworm Team (G0034)": {
        "T0855": 3,  # CRASHOVERRIDE issued direct breaker-open commands
        "T0836": 2,  # manipulated protection relay settings
        "T0815": 2,  # operator-visibility disruption components
        "T0879": 2,  # SIPROTEC-disabling component risked equipment damage
    },
    "Volt Typhoon (VOLTZITE, G1017)": {
        "T0888": 3,  # reconnaissance/discovery is the documented core behavior
        # No weight on T0831/T0836/T0879/T0855/T0815: not publicly reported
        # to have taken destructive action against ICS processes as of the
        # sources above. This is the point, not an oversight.
    },
    "ALLANITE": {
        "T0888": 2,  # reconnaissance-oriented, Dragonfly-lineage tactics
        # Same reasoning as Volt Typhoon: MITRE's own description states no
        # disruptive/destructive capability has been observed.
    },
}


def score_attribution(mitre_hits: set[str]) -> tuple[dict[str, int], str | None, list[str]]:
    """Score actors by matched-technique weight, normalized against the
    strongest match (not against each actor's own profile total) — otherwise
    a narrow actor profile trivially hits 100% the moment its few techniques
    appear, even when a better-evidenced actor also matches everything.

    Returns (scores, leader, tied_with). When two or more actors land at the
    exact top score, picking one as "the leader" by dict/insertion order
    would imply a confidence the technique-overlap-only model doesn't
    actually have — for this project's demo narrative, Xenotime and
    Sandworm genuinely do tie, because the scripted scenario includes
    technique T0855 and T0836, which are documented for both groups. A real
    investigator would need additional evidence (malware artifacts, C2
    infrastructure, the specific asset type targeted) to break a tie like
    this; the API surfaces the tie explicitly instead of hiding it."""
    raw: dict[str, int] = {}
    for actor, weights in ACTOR_PROFILES.items():
        raw[actor] = sum(w for tech, w in weights.items() if tech in mitre_hits)
    peak = max(raw.values(), default=0)
    scores = {actor: (round(val / peak * 100) if peak else 0) for actor, val in raw.items()}
    if peak == 0:
        return scores, None, []
    top = sorted([a for a, v in raw.items() if v == peak])
    leader, tied_with = top[0], top[1:]
    return scores, leader, tied_with
