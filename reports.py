import io
import json
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

from sqlalchemy.orm import Session

from . import models
from .config import settings
from .blockchain import chain_status
from .forensics import backward_walk, attribution, verify_chain_integrity
from .threat_intel import MITRE_TECHNIQUES

# Design tokens — matches the dashboard's palette (styles.css), so the PDF
# doesn't look like a disconnected default reportlab document.
NAVY = colors.HexColor("#3F5066")
NAVY_DEEP = colors.HexColor("#2B3648")
STONE = colors.HexColor("#DCD8D2")
BG = colors.HexColor("#F6F2F0")
CRITICAL = colors.HexColor("#9C4A3C")
CRITICAL_BG = colors.HexColor("#F3E4E0")
SAFE = colors.HexColor("#6E8271")
SAFE_BG = colors.HexColor("#E7ECE5")
MUTED = colors.HexColor("#8B8681")


def generate_report_pdf(db: Session, start_block_id: int) -> bytes:
    steps = backward_walk(db, start_block_id)
    scores, leader, tied_with = attribution(db)
    hit_techniques = {a.technique for a in db.query(models.Anomaly).filter(models.Anomaly.technique.isnot(None))}
    chain_length, chain_verified, mismatches = verify_chain_integrity(db)
    chain = chain_status()

    title_style = ParagraphStyle("ReportTitle", fontName="Times-Bold", fontSize=20, leading=24,
                                  textColor=NAVY_DEEP, spaceAfter=2)
    kicker_style = ParagraphStyle("Kicker", fontName="Helvetica", fontSize=9, textColor=MUTED, spaceAfter=14)
    h2 = ParagraphStyle("H2", fontName="Times-Bold", fontSize=13, textColor=NAVY_DEEP,
                         spaceBefore=16, spaceAfter=6)
    body = ParagraphStyle("Body", fontName="Helvetica", fontSize=9.5, leading=14, textColor=colors.HexColor("#2A2A28"))
    body_muted = ParagraphStyle("BodyMuted", parent=body, textColor=MUTED, fontSize=8.5)
    mono_small = ParagraphStyle("MonoSmall", fontName="Courier", fontSize=7.5, leading=10)

    story = []

    # ---- Header ----
    story.append(Paragraph("IRONLEDGER", ParagraphStyle(
        "Wordmark", fontName="Helvetica-Bold", fontSize=10, textColor=NAVY, spaceAfter=2)))
    story.append(Paragraph("Forensic Incident Report — Reactor-01", title_style))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Generated {generated}", kicker_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=NAVY, spaceAfter=12))

    # ---- Chain integrity badge + metadata ----
    badge_color, badge_bg, badge_text = (
        (CRITICAL, CRITICAL_BG, "TAMPER DETECTED") if not chain_verified else (SAFE, SAFE_BG, "CHAIN VERIFIED")
    )
    anchor_desc = (
        f"Ethereum Sepolia (contract {_short(settings.contract_address)})"
        if chain["configured"] else "Local mode — not anchored to a public chain"
    )
    meta_table = Table([[
        _badge(badge_text, badge_color, badge_bg),
        Paragraph(
            f"<b>Anchoring:</b> {anchor_desc}"
            f"<br/><b>Blocks in chain:</b> {chain_length} &nbsp;&nbsp; "
            f"<b>Mismatches:</b> {len(mismatches) if mismatches else 'none'}", body),
    ]], colWidths=[110, 380])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # ---- Executive summary (composed from live data, not static text) ----
    story.append(Paragraph("Executive Summary", h2))
    tamper_note = (
        f"Hash-chain verification against the anchored evidence ledger found "
        f"{len(mismatches)} block(s) inconsistent with their on-chain commitment "
        f"(block {', '.join('#' + str(m) for m in mismatches)}), confirming a post-hoc "
        f"alteration attempt." if mismatches else
        "Hash-chain verification found no inconsistencies between the anchored ledger and "
        "its off-chain records."
    )
    attr_note = (
        (f"Technique correlation identifies <b>{leader}</b>"
         + (f" (tied with {', '.join(tied_with)})" if tied_with else "")
         + f" as most consistent with the observed behavior, based on "
           f"{len(hit_techniques)} correlated MITRE ATT&amp;CK for ICS technique(s).")
        if leader else "No MITRE ATT&amp;CK for ICS techniques were correlated in this run."
    )
    story.append(Paragraph(
        f"This report documents a reconstructed incident spanning {len(steps)} ledger "
        f"entries, from the identified root cause through to the investigation trigger. "
        f"{tamper_note} {attr_note}", body,
    ))

    # ---- Methodology ----
    story.append(Paragraph("Methodology", h2))
    for label, desc in [
        ("Evidence ledger", "Every command and telemetry report is hashed as "
         "H(source, command, entity, params, prevHash) and chained to the prior entry, "
         "anchored on-chain where configured."),
        ("Anomaly detection", "A dual-layer approach: hard physics-envelope thresholds "
         "(pressure/temperature/vibration/interlock consistency) plus a scikit-learn "
         "Isolation Forest trained on baseline telemetry."),
        ("Forensic reconstruction", "A backward walk from the investigation trigger "
         "through prevHash pointers to the earliest anomaly-associated entry, flagging "
         "any point where the off-chain record no longer reproduces its anchored hash."),
        ("Threat attribution", "Correlated MITRE ATT&amp;CK for ICS techniques are scored "
         "against documented threat-actor technique profiles (see Sources, below), "
         "normalized against the strongest match rather than each actor's own profile "
         "total, and reported as a tie when the evidence doesn't distinguish further."),
    ]:
        story.append(Paragraph(f"<b>{label}.</b> {desc}", body))

    # ---- Chain of custody / integrity verification ----
    story.append(Paragraph("Chain-of-Custody Verification", h2))
    story.append(Paragraph(
        "Two independent checks were run against the full ledger: per-block tamper "
        "(does recomputing each block's hash from its current off-chain fields still "
        "match what was anchored?) and chain-link continuity (does each block's prevHash "
        "match the previous block's anchored hash?).", body,
    ))
    custody_data = [
        ["Check", "Result"],
        ["Chain length", str(chain_length)],
        ["Overall status", "TAMPERED / BROKEN LINK" if not chain_verified else "VERIFIED"],
        ["Affected block(s)", ", ".join(f"#{m}" for m in mismatches) if mismatches else "none"],
    ]
    story.append(_table(custody_data, highlight_row=2 if not chain_verified else None))

    # ---- Reconstructed timeline ----
    story.append(Paragraph("Reconstructed Timeline (Backward-Walk)", h2))
    tl_data = [["Block", "Time (UTC)", "Event", "Flag"]]
    tamper_rows, root_rows = [], []
    for i, s in enumerate(steps, start=1):
        ts = s["ts"]
        ts_str = ts.strftime("%H:%M:%S") if hasattr(ts, "strftime") else str(ts)
        tl_data.append([f"#{s['block_id']}", ts_str, s["title"], (s["flag"] or "—").upper()])
        if s["flag"] == "tamper":
            tamper_rows.append(i)
        elif s["flag"] == "root":
            root_rows.append(i)
    story.append(_table(tl_data, tamper_rows=tamper_rows, root_rows=root_rows))

    # ---- MITRE techniques ----
    story.append(Paragraph("MITRE ATT&amp;CK for ICS Techniques Observed", h2))
    mitre_data = [["ID", "Technique", "Tactic"]]
    for t in MITRE_TECHNIQUES:
        if t["id"] in hit_techniques:
            mitre_data.append([t["id"], t["name"], t["tactic"]])
    story.append(_table(mitre_data))

    # ---- Attribution ----
    story.append(Paragraph("Threat Attribution", h2))
    attr_data = [["Actor", "Confidence"]] + [[actor, f"{score}%"] for actor, score in
                                              sorted(scores.items(), key=lambda kv: -kv[1])]
    story.append(_table(attr_data))
    if tied_with:
        story.append(Paragraph(
            f"<b>Note on tie:</b> {leader} and {', '.join(tied_with)} are tied on "
            f"technique-overlap alone. Disambiguating further would require additional "
            f"evidence (malware artifacts, C2 infrastructure, or the specific asset type "
            f"targeted) beyond what this technique-correlation model considers.", body_muted,
        ))
    story.append(Paragraph(
        "Sources: XENOTIME/TEMP.Veles — MITRE ATT&amp;CK Group G0088; Sandworm Team — "
        "G0034; Volt Typhoon/VOLTZITE — G1017; ALLANITE — MITRE ATT&amp;CK for ICS group "
        "knowledge base (Dragos). Full citations in backend/app/threat_intel.py.",
        body_muted,
    ))

    # ---- On-chain proof appendix ----
    onchain_rows = []
    for s in steps:
        block = db.query(models.LedgerBlock).filter(models.LedgerBlock.id == s["block_id"]).first()
        if block and block.tx_hash:
            link = (f'<link href="https://sepolia.etherscan.io/tx/{block.tx_hash}" '
                    f'color="#3F5066">{_short(block.tx_hash)}</link>')
            onchain_rows.append([f"#{block.id}", Paragraph(link, mono_small)])
    if onchain_rows:
        story.append(Paragraph("On-Chain Proof (Sepolia)", h2))
        story.append(Paragraph(
            "The following blocks were anchored as real Sepolia transactions. Click a "
            "hash (in the PDF, not this preview) to view it independently on Etherscan.",
            body_muted,
        ))
        story.append(_table([["Block", "Transaction"]] + onchain_rows))

    # ---- Signature block ----
    story.append(Spacer(1, 36))
    sig_table = Table([[
        Paragraph("_______________________________<br/>Investigator signature", body),
        Paragraph("_______________________________<br/>Chain-of-custody witness", body),
    ]], colWidths=[245, 245])
    story.append(sig_table)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.65 * inch, rightMargin=0.65 * inch, title="IronLedger Forensic Report",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(STONE)
    canvas.setLineWidth(0.5)
    canvas.line(0.65 * inch, 0.55 * inch, letter[0] - 0.65 * inch, 0.55 * inch)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.65 * inch, 0.4 * inch, "IronLedger — Confidential Forensic Report")
    canvas.drawRightString(letter[0] - 0.65 * inch, 0.4 * inch, f"Page {doc.page}")
    canvas.restoreState()


def _badge(text: str, fg, bg) -> Table:
    t = Table([[text]], colWidths=[100])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("TEXTCOLOR", (0, 0), (-1, -1), fg),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _short(hash_hex: str) -> str:
    if not hash_hex:
        return "—"
    return hash_hex if len(hash_hex) <= 20 else f"{hash_hex[:10]}…{hash_hex[-8:]}"


def _table(data, highlight_row: int | None = None, tamper_rows=None, root_rows=None) -> Table:
    tamper_rows = tamper_rows or []
    root_rows = root_rows or []
    t = Table(data, hAlign="LEFT", repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, STONE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    if highlight_row is not None:
        style.append(("BACKGROUND", (0, highlight_row), (-1, highlight_row), CRITICAL_BG))
        style.append(("TEXTCOLOR", (0, highlight_row), (-1, highlight_row), CRITICAL))
    for r in tamper_rows:
        style.append(("BACKGROUND", (0, r), (-1, r), CRITICAL_BG))
        style.append(("TEXTCOLOR", (0, r), (-1, r), CRITICAL))
    for r in root_rows:
        style.append(("BACKGROUND", (0, r), (-1, r), SAFE_BG))
        style.append(("TEXTCOLOR", (0, r), (-1, r), SAFE))
    t.setStyle(TableStyle(style))
    return t
