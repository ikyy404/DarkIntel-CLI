import sqlite3
import os
import json

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from xml.sax.saxutils import escape


DB_NAME = "darkintel.db"
OUTPUT_DIR = "reports"


def safe(value):
    if value is None or str(value).strip() == "":
        return "Not Available"

    return escape(str(value))

def get_data(conn):
    cursor = conn.cursor()

    intel = cursor.execute(
        """
        SELECT
            item_key,
            title,
            source_date,
            due_date,
            cwes,
            known_ransomware_use,
            smart_risk_score,
            smart_risk_level,
            exploitability_signal,
            remediation_status
        FROM intel_items
        WHERE source_name = 'CISA KEV'
        ORDER BY smart_risk_score DESC, id DESC
        """
    ).fetchall()

    breach_total = cursor.execute(
        "SELECT COUNT(*) FROM public_breach_catalog"
    ).fetchone()[0]

    ransomware = cursor.execute(
        """
        SELECT
            title,
            threat_category,
            published_date,
            link
        FROM ransomware_reports
        ORDER BY id DESC
        """
    ).fetchall()

    breaches = cursor.execute(
        """
        SELECT
            title,
            domain,
            breach_date,
            pwn_count,
            data_classes
        FROM public_breach_catalog
        ORDER BY breach_date DESC
        LIMIT 20
        """
    ).fetchall()

    exposures = cursor.execute(
        """
        SELECT
            domain,
            source_name,
            exposure_date,
            exposure_status,
            verification_status
        FROM domain_exposures
        WHERE data_classification = 'PUBLIC_BREACH_METADATA'
        ORDER BY exposure_date DESC
        """
    ).fetchall()

    return intel, ransomware, breaches, breach_total, exposures

def build_styles():
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            fontSize=26,
            leading=32,
            textColor=colors.HexColor("#172554"),
            alignment=TA_CENTER,
            spaceAfter=15
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=15,
            textColor=colors.HexColor("#1D4ED8"),
            spaceBefore=12,
            spaceAfter=8
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11
        )
    )

    return styles


def add_page(canvas, doc):
    canvas.saveState()

    width, height = A4

    canvas.setStrokeColor(
        colors.HexColor("#CBD5E1")
    )

    canvas.line(
        18 * mm,
        15 * mm,
        width - 18 * mm,
        15 * mm
    )

    canvas.setFont("Helvetica", 8)

    canvas.setFillColor(
        colors.HexColor("#64748B")
    )

    canvas.drawString(
        18 * mm,
        10 * mm,
        "DARKINTEL-CLI | PUBLIC THREAT INTELLIGENCE"
    )

    canvas.drawRightString(
        width - 18 * mm,
        10 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


def make_table(data, widths=None):
    table = Table(
        data,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT"
    )

    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#172554")),

            ("TEXTCOLOR", (0, 0), (-1, 0),
             colors.white),

            ("FONTNAME", (0, 0), (-1, 0),
             "Helvetica-Bold"),

            ("FONTSIZE", (0, 0), (-1, -1), 7),

            ("GRID", (0, 0), (-1, -1), 0.4,
             colors.HexColor("#CBD5E1")),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F1F5F9")]),

            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    return table


def generate_pdf():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    filename = datetime.now().strftime(
        "DarkIntel_Report_%Y%m%d_%H%M%S.pdf"
    )

    filepath = os.path.join(
        OUTPUT_DIR,
        filename
    )

    conn = sqlite3.connect(DB_NAME)

    try:
        intel, ransomware, breaches, breach_total, exposures = get_data(conn)
    finally:
        conn.close()

    styles = build_styles()

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title="DarkIntel CTI Report",
        author="DarkIntel-CLI"
    )

    story = []

    generated = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M UTC")

    # COVER
    story.append(Spacer(1, 45 * mm))

    story.append(
        Paragraph(
            "DARKINTEL-CLI",
            styles["CoverTitle"]
        )
    )

    story.append(
        Paragraph(
            "CYBER THREAT INTELLIGENCE REPORT",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 12 * mm))

    story.append(
        Paragraph(
            f"Generated: {generated}",
            styles["BodyText"]
        )
    )

    story.append(
        Paragraph(
            "Classification: Public Intelligence",
            styles["BodyText"]
        )
    )

    story.append(PageBreak())

    # EXECUTIVE SUMMARY
    story.append(
        Paragraph(
            "1. Executive Summary",
            styles["SectionTitle"]
        )
    )

    levels = {}

    for record in intel:
        level = record[7] or "Unassessed"
        levels[level] = levels.get(level, 0) + 1

    ransomware_count = len(ransomware)

    story.append(
        Paragraph(
            f"Total CISA KEV records: {len(intel)}",
            styles["BodyText"]
        )
    )

    story.append(
        Paragraph(
            f"Public ransomware and malware reports: "
            f"{ransomware_count}",
            styles["BodyText"]
        )
    )

    story.append(Spacer(1, 5 * mm))

    # RISK OVERVIEW
    story.append(
        Paragraph(
            "2. Smart Risk Overview",
            styles["SectionTitle"]
        )
    )

    risk_data = [
        ["Risk Level", "Record Count"]
    ]

    for level, count in sorted(levels.items()):
        risk_data.append([level, str(count)])

    story.append(make_table(risk_data))

    story.append(Spacer(1, 8 * mm))

    # VULNERABILITY ANALYSIS
    story.append(
        Paragraph(
            "3. Vulnerability Analysis",
            styles["SectionTitle"]
        )
    )

    vuln_data = [[
        "CVE",
        "Score",
        "Level",
        "Remediation"
    ]]

    for record in intel:
        vuln_data.append([
            safe(record[0]),
            str(record[6] or 0),
            safe(record[7]),
            safe(record[9])
        ])

    story.append(
        make_table(
            vuln_data,
            [40 * mm, 18 * mm, 25 * mm, 65 * mm]
        )
    )

    story.append(Spacer(1, 8 * mm))

    # DETAILED RECORDS
    story.append(
        Paragraph(
            "4. Detailed Intelligence Records",
            styles["SectionTitle"]
        )
    )

    for record in intel:
        (
            cve,
            title,
            source_date,
            due_date,
            cwes,
            ransomware_use,
            score,
            level,
            exploit_signal,
            remediation
        ) = record

        story.append(
            Paragraph(
                f"<b>{safe(cve)}</b>",
                styles["BodyText"]
            )
        )

        details = (
            f"Title: {safe(title)}<br/>"
            f"Source Date: {safe(source_date)}<br/>"
            f"Remediation Due Date: {safe(due_date)}<br/>"
            f"CWE: {safe(cwes)}<br/>"
            f"Ransomware Use: {safe(ransomware_use)}<br/>"
            f"Smart Risk: {score or 0}/100 "
            f"({safe(level)})<br/>"
            f"Exploitability Signal: {safe(exploit_signal)}<br/>"
            f"Remediation Status: {safe(remediation)}"
        )

        story.append(
            Paragraph(
                details,
                styles["SmallText"]
            )
        )

        story.append(Spacer(1, 4 * mm))

    # RANSOMWARE AND MALWARE
    story.append(
        Paragraph(
            "5. Ransomware & Malware Intelligence",
            styles["SectionTitle"]
        )
    )

    if ransomware:
        malware_data = [[
            "Category",
            "Title",
            "Published"
        ]]

        for item in ransomware:
            malware_data.append([
                safe(item[1]),
                safe(item[0]),
                safe(item[2])
            ])

        story.append(
            make_table(
                malware_data,
                [30 * mm, 90 * mm, 40 * mm]
            )
        )
    else:
        story.append(
            Paragraph(
                "No public reports available.",
                styles["BodyText"]
            )
        )

    # PUBLIC BREACH INTELLIGENCE
    story.append(
        Paragraph(
            "6. Public Breach Intelligence",
            styles["SectionTitle"]
        )
    )

    story.append(
        Paragraph(
            f"Total public breach catalog records: {breach_total}",
            styles["BodyText"]
        )
    )

    if breaches:
        breach_data = [[
            "Breach Name",
            "Domain",
            "Breach Date",
            "Accounts",
            "Data Classes"
        ]]

        for item in breaches:
            try:
                classes = json.loads(item[4] or "[]")

                if isinstance(classes, list):
                    classes_text = ", ".join(
                        str(value) for value in classes
                    )
                else:
                    classes_text = str(classes)

            except (TypeError, ValueError):
                classes_text = str(item[4] or "Not specified")

            breach_data.append([
                Paragraph(safe(item[0] or "Unknown"), styles["SmallText"]),
                Paragraph(safe(item[1] or "Unknown"), styles["SmallText"]),
                Paragraph(safe(item[2] or "Unknown"), styles["SmallText"]),
                Paragraph(str(item[3] or 0), styles["SmallText"]),
                Paragraph(safe(classes_text), styles["SmallText"])
            ])

        story.append(
            make_table(
                breach_data,
                [38 * mm, 34 * mm, 24 * mm, 20 * mm, 58 * mm]
            )
        )
    else:
        story.append(
            Paragraph(
                "No public breach catalog records available.",
                styles["BodyText"]
            )
        )
    # DOMAIN EXPOSURE INTELLIGENCE
    story.append(
        Paragraph(
            "7. Domain Exposure Intelligence",
            styles["SectionTitle"]
        )
    )

    story.append(
        Paragraph(
            f"Total matching metadata records: {len(exposures)}",
            styles["BodyText"]
        )
    )

    if exposures:
        exposure_data = [[
            "Domain",
            "Source",
            "Breach Date",
            "Status",
            "Verification"
        ]]

        for item in exposures:
            exposure_data.append([
                Paragraph(safe(item[0]), styles["SmallText"]),
                Paragraph(safe(item[1]), styles["SmallText"]),
                Paragraph(safe(item[2]), styles["SmallText"]),
                Paragraph(safe(item[3]), styles["SmallText"]),
                Paragraph(safe(item[4]), styles["SmallText"])
            ])

        story.append(
            make_table(
                exposure_data,
                [35 * mm, 35 * mm, 25 * mm, 40 * mm, 39 * mm]
            )
        )
    else:
        story.append(
            Paragraph(
                "No public domain exposure metadata available.",
                styles["BodyText"]
            )
        )

    story.append(Spacer(1, 3 * mm))

    story.append(
        Paragraph(
            "Assessment Note: Public breach catalog metadata "
            "does not confirm domain ownership, account exposure, "
            "or organizational compromise. No passwords or "
            "credentials are collected or stored.",
            styles["SmallText"]
        )
    )
    story.append(Spacer(1, 8 * mm))

    # RECOMMENDATIONS
    story.append(
        Paragraph(
            "8. Recommendations",
            styles["SectionTitle"]
        )
    )

    recommendations = [
        "Prioritize remediation of vulnerabilities listed in CISA KEV.",
        "Review affected assets before determining organizational exposure.",
        "Monitor public security advisories for emerging threats.",
        "Validate vulnerability information using independent sources.",
        "Maintain an updated vulnerability management process."
    ]

    for recommendation in recommendations:
        story.append(
            Paragraph(
                f"- {recommendation}",
                styles["BodyText"]
            )
        )

    # LIMITATIONS
    story.append(
        Paragraph(
            "9. Assessment Limitations",
            styles["SectionTitle"]
        )
    )
    story.append(
        Paragraph(
            "This report uses public CISA KEV metadata, CISA RSS "
            "advisories, and HIBP public breach catalog metadata. "
            "CISA KEV inclusion indicates known exploitation of "
            "a vulnerability, but does not confirm compromise or "
            "exposure of any particular organization. Smart Risk "
            "Score is an internal triage score, not a probability "
            "of compromise. Missing CVSS or corroboration data "
            "remains unverified. Remediation status refers to the "
            "recorded CISA due date. Public breach metadata does "
            "not confirm exposure of any specific user, account, "
            "or organization. No leaked passwords or credentials "
            "are collected or stored.",
            styles["SmallText"]
        )
    )
    # DATA SOURCES
    story.append(
        Paragraph(
            "10. Data Sources",
            styles["SectionTitle"]
        )
    )

    sources = [
        "CISA Known Exploited Vulnerabilities (KEV): "
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",

        "CISA Cybersecurity Advisories: "
        "https://www.cisa.gov/news-events/cybersecurity-advisories",

        "Have I Been Pwned (HIBP) Public Breach Catalog: "
        "https://haveibeenpwned.com/"
    ]

    for source in sources:
        story.append(
            Paragraph(
                f"- {safe(source)}",
                styles["SmallText"]
            )
        )

    story.append(Spacer(1, 5 * mm))
    doc.build(
        story,
        onFirstPage=add_page,
        onLaterPages=add_page
    )

    print("\n======================================")
    print("       DARKINTEL PDF EXPORTER")
    print("======================================")
    print(f"[+] PDF generated: {filepath}")
    print(f"[+] Vulnerability records: {len(intel)}")
    print(f"[+] Public threat reports: {len(ransomware)}")
    print("[+] Export completed successfully.")


if __name__ == "__main__":
    try:
        generate_pdf()

    except (sqlite3.Error, OSError, ValueError) as error:
        print(f"[ERROR] {error}")

