import sqlite3
import json

from pathlib import Path
from datetime import datetime, timezone


DB_NAME = "darkintel.db"
REPORT_DIR = Path("reports")


def clean_cell(value):
    """Clean values before placing them in Markdown tables."""
    if value is None or str(value).strip() == "":
        return "Not provided"

    return (
        str(value)
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .strip()
    )


def load_intelligence():
    """Load analyzed CISA KEV records from SQLite."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        records = cursor.execute(
            """
            SELECT
                item_key,
                title,
                link,
                source_date,
                description,
                known_ransomware_use,
                due_date,
                cwes,
                risk_priority,
                confidence_score,
                confidence_level,
                verification_status,
                analysis_notes,
                is_simulated
            FROM intel_items
            WHERE source_name = ?
            ORDER BY source_date DESC
            """,
            ("CISA KEV",)
        ).fetchall()

        return records

    finally:
        conn.close()


def load_public_breach_catalog():
    """Load public breach metadata from the local HIBP catalog."""

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        records = cursor.execute("""
            SELECT
                breach_name,
                title,
                domain,
                breach_date,
                added_date,
                pwn_count,
                data_classes,
                is_verified,
                is_fabricated,
                is_spam_list,
                is_malware,
                is_stealer_log,
                fetched_at
            FROM public_breach_catalog
            ORDER BY breach_date DESC
        """).fetchall()

        return records

    finally:
        conn.close()
def load_domain_exposures():
    """Load public domain exposure metadata from SQLite."""

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        records = cursor.execute("""
            SELECT
                domain,
                source_name,
                exposure_date,
                exposure_status,
                verification_status,
                data_classification,
                checked_at
            FROM domain_exposures
            WHERE data_classification = 'PUBLIC_BREACH_METADATA'
            ORDER BY exposure_date DESC
        """).fetchall()

        return records

    finally:
        conn.close()
def build_report(records, breach_records, exposure_records):
    """Build an English-language CTI report."""

    generated_at = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(records)

    priority_counts = {}
    verification_counts = {}

    for record in records:
        priority = record["risk_priority"] or "Unassessed"
        verification = (
            record["verification_status"] or "Unreviewed"
        )

        priority_counts[priority] = (
            priority_counts.get(priority, 0) + 1
        )

        verification_counts[verification] = (
            verification_counts.get(verification, 0) + 1
        )

    lines = [
        "# DARKINTEL-CLI",
        "## Cyber Threat Intelligence Report",
        "",
        f"**Generated:** {generated_at}",
        "**Intelligence Source:** CISA Known Exploited Vulnerabilities (KEV)",
        "**Report Language:** English",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        (
            f"This report contains {total} vulnerability intelligence "
            "records collected from the public CISA KEV catalog."
        ),
        "",
        (
            "These records identify vulnerabilities listed by CISA "
            "as known to have been exploited. Their presence does not "
            "confirm exposure or compromise of any specific organization."
        ),
        "",
        "## 2. Intelligence Overview",
        "",
        f"- Total records: {total}",
    ]

    for priority, count in sorted(priority_counts.items()):
        lines.append(f"- {priority}: {count}")
    lines.extend([
        "",
        "### Verification Status",
        ""
    ])

    for status, count in sorted(verification_counts.items()):
        lines.append(f"- {status}: {count}")

    lines.extend([
        "",
        "## 3. Vulnerability Analysis",
        "",
        "| CVE ID | Priority | Confidence | Verification |",
        "|---|---|---|---|"
    ])

    for record in records:
        cve_id = clean_cell(record["item_key"])
        priority = clean_cell(record["risk_priority"])
        confidence = (
            f'{record["confidence_score"]}/100 '
            f'({clean_cell(record["confidence_level"])})'
        )
        verification = clean_cell(
            record["verification_status"]
        )

        lines.append(
            f"| {cve_id} | {priority} | "
            f"{confidence} | {verification} |"
        )

    lines.extend([
        "",
        "## 4. Detailed Intelligence Records",
        ""
    ])

    for index, record in enumerate(records, start=1):
        lines.extend([
            f"### 4.{index} — {clean_cell(record['item_key'])}",
            "",
            f"**Title:** {clean_cell(record['title'])}",
            f"**Source Date:** {clean_cell(record['source_date'])}",
            f"**Known Ransomware Use:** {clean_cell(record['known_ransomware_use'])}",
            f"**Remediation Due Date:** {clean_cell(record['due_date'])}",
            f"**CWEs:** {clean_cell(record['cwes'])}",
            f"**Risk Priority:** {clean_cell(record['risk_priority'])}",
            (
                f"**Confidence:** {record['confidence_score']}/100 "
                f"({clean_cell(record['confidence_level'])})"
            ),
            f"**Verification:** {clean_cell(record['verification_status'])}",
            f"**Simulated Record:** {bool(record['is_simulated'])}",
            "",
            "**Description:**",
            "",
            clean_cell(record["description"]),
            "",
            "**Analysis Notes:**",
            "",
            clean_cell(record["analysis_notes"]),
            "",
            f"**Reference:** {clean_cell(record['link'])}",
            ""
        ])

    lines.extend([
        "## 5. Public Breach Intelligence",
        "",
        f"- Total public breach catalog records: {len(breach_records)}",
        "- Intelligence Source: Have I Been Pwned (HIBP)",
        "",
        "### Recent Public Breach Records",
        "",
        "| Breach | Domain | Breach Date | Reported Accounts | Data Classes |",
        "|---|---|---|---:|---|"
    ])

    for record in breach_records[:20]:
        try:
            data_classes = json.loads(
                record["data_classes"] or "[]"
            )
        except (json.JSONDecodeError, TypeError):
            data_classes = []

        if not isinstance(data_classes, list):
            data_classes = []

        classes_text = ", ".join(
            str(item) for item in data_classes
        ) or "Not provided"

        lines.append(
            f"| {clean_cell(record['title'])} "
            f"| {clean_cell(record['domain'])} "
            f"| {clean_cell(record['breach_date'])} "
            f"| {clean_cell(record['pwn_count'])} "
            f"| {clean_cell(classes_text)} |"
        )

    lines.extend([
        "",
        "**Important:** Reported account counts are figures supplied "
        "by HIBP for each public breach entry. They do not establish "
        "that any specific user or organization was affected.",
        ""
    ])
    lines.extend([
        "## 6. Domain Exposure Intelligence",
        "",
        f"- Total matching metadata records: {len(exposure_records)}",
        "",
        "| Domain | Source | Breach Date | Status | Verification |",
        "|---|---|---|---|---|"
    ])

    for record in exposure_records:
        lines.append(
            f"| {clean_cell(record['domain'])} "
            f"| {clean_cell(record['source_name'])} "
            f"| {clean_cell(record['exposure_date'])} "
            f"| {clean_cell(record['exposure_status'])} "
            f"| {clean_cell(record['verification_status'])} |"
        )

    lines.extend([
        "",
        "**Assessment Note:** These entries represent public breach "
        "catalog metadata matches only. They do not confirm domain "
        "ownership, account exposure, or organizational compromise.",
        "No passwords or credentials were collected or stored.",
        ""
    ])
    lines.extend([
        "## 7. Recommendations",
        "",
        "1. Identify whether affected products are present in the organization's asset inventory.",
        "2. Verify installed product versions against vendor security advisories.",
        "3. Prioritize remediation using the applicable vendor guidance and CISA KEV deadlines.",
        "4. Apply security updates through the organization's approved change-management process.",
        "5. Review relevant security logs for signs of suspicious activity.",
        "6. Document findings and independently verify any suspected compromise.",
        "",
        "## 8. Assessment Limitations",
        "",
        "- CISA KEV inclusion is not proof of compromise.",
        "- Local organizational exposure has not been assessed by this report.",
        "- Independent corroboration has not been established unless explicitly documented.",
        "- Confidence scores represent source and metadata completeness, not breach probability.",
        "- A remediation due date is not a breach date.",
        "",
        "## 9. Data Source",
        "",
        "CISA Known Exploited Vulnerabilities Catalog:",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "",
        "---",
        "",
        "*Generated automatically by DarkIntel-CLI.*",
        ""
    ])

    return "\n".join(lines)


def save_report(report):
    """Save the report as a Markdown file."""

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    filename = f"CTI_Report_{timestamp}.md"
    output_path = REPORT_DIR / filename

    output_path.write_text(
        report,
        encoding="utf-8"
    )

    return output_path


def main():
    print("=" * 45)
    print("       DARKINTEL-CLI REPORT GENERATOR")
    print("=" * 45)

    try:
        records = load_intelligence()
        breach_records = load_public_breach_catalog()
        exposure_records = load_domain_exposures()

        if not records:
            print("[!] No CISA intelligence records found.")
            return

        print(f"[+] Loaded records: {len(records)}")
        print(
            f"[+] Public breach records: {len(breach_records)}"
        )
        print(
            f"[+] Domain exposure metadata: {len(exposure_records)}"
        )

        report = build_report(
            records,
            breach_records,
            exposure_records
        )

        output_path = save_report(report)

        print("[+] CTI report generated successfully.")
        print(f"[+] Output: {output_path}")

    except sqlite3.Error as error:
        print(f"[DATABASE ERROR] {error}")

    except OSError as error:
        print(f"[FILE ERROR] {error}")
if __name__ == "__main__":
    main()
