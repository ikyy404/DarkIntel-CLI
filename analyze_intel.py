
import sqlite3
import json
import re

from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlparse


# ==========================================
# CONFIGURATION
# ==========================================

DB_NAME = "darkintel.db"

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

ALLOWED_HOST = "www.cisa.gov"

MAX_RESPONSE_SIZE = 10 * 1024 * 1024


# ==========================================
# DATABASE MIGRATION
# ==========================================

def upgrade_analysis_schema(conn):

    cursor = conn.cursor()

    existing_columns = {
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(intel_items)"
        ).fetchall()
    }

    new_columns = [

        ("known_ransomware_use", "TEXT DEFAULT 'Unknown'"),

        ("due_date", "TEXT"),

        ("cwes", "TEXT"),

        ("risk_priority", "TEXT DEFAULT 'Unassessed'"),

        ("confidence_score", "INTEGER DEFAULT 0"),

        ("confidence_level", "TEXT DEFAULT 'Low'"),

        ("analysis_notes", "TEXT"),

        ("analyzed_at", "TEXT")

    ]

    for name, data_type in new_columns:

        if name not in existing_columns:

            cursor.execute(
                f"ALTER TABLE intel_items ADD COLUMN "
                f"{name} {data_type}"
            )

            print(f"[+] Added analysis column: {name}")

    conn.commit()


# ==========================================
# FETCH CISA METADATA
# ==========================================

def fetch_cisa_metadata():

    parsed = urlparse(FEED_URL)

    if (
        parsed.scheme != "https"
        or parsed.hostname != ALLOWED_HOST
    ):
        raise ValueError("Untrusted feed URL.")

    request = Request(
        FEED_URL,
        headers={
            "User-Agent": "DarkIntel-CLI/1.0",
            "Accept": "application/json"
        }
    )

    with urlopen(request, timeout=20) as response:

        raw_data = response.read(
            MAX_RESPONSE_SIZE + 1
        )

    if len(raw_data) > MAX_RESPONSE_SIZE:

        raise ValueError("Feed exceeds size limit.")

    data = json.loads(raw_data.decode("utf-8"))

    vulnerabilities = data.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):

        raise ValueError("Invalid CISA feed structure.")

    metadata = {}

    for item in vulnerabilities:

        cve_id = item.get("cveID", "")

        if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):

            metadata[cve_id] = item

    print("[+] CISA metadata refreshed.")

    return metadata


# ==========================================
# CONFIDENCE CALCULATION
# ==========================================

def calculate_analysis_confidence(item):

    source_score = 35

    metadata_score = 0

    if item.get("vendorProject"):
        metadata_score += 5

    if item.get("product"):
        metadata_score += 5

    if item.get("vulnerabilityName"):
        metadata_score += 5

    if item.get("shortDescription"):
        metadata_score += 10

    if item.get("requiredAction"):
        metadata_score += 5

    corroboration_score = 0

    total = (
        source_score
        + metadata_score
        + corroboration_score
    )

    if total < 40:
        level = "Low"

    elif total < 70:
        level = "Medium"

    else:
        level = "High"

    return total, level


# ==========================================
# RISK PRIORITY CLASSIFICATION
# ==========================================

def classify_priority(item):

    ransomware = item.get(
        "knownRansomwareCampaignUse",
        "Unknown"
    )

    required_fields = [

        item.get("vendorProject"),

        item.get("product"),

        item.get("shortDescription")

    ]

    if not all(required_fields):

        return "Insufficient Data"

    if ransomware == "Known":

        return "High Attention"

    return "Standard Review"


# ==========================================
# ANALYZE DATABASE RECORDS
# ==========================================

def analyze_records(conn, metadata):

    cursor = conn.cursor()

    records = cursor.execute(
        """
        SELECT id, item_key
        FROM intel_items
        WHERE source_name = ?
        """,
        ("CISA KEV",)
    ).fetchall()

    analyzed = 0

    skipped = 0

    analyzed_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    for record_id, cve_id in records:

        item = metadata.get(cve_id)

        if item is None:

            print(f"[!] Metadata unavailable: {cve_id}")

            skipped += 1

            continue

        score, level = calculate_analysis_confidence(
            item
        )

        priority = classify_priority(item)

        ransomware = item.get(
            "knownRansomwareCampaignUse",
            "Unknown"
        )

        due_date = item.get("dueDate", "")

        cwes = ", ".join(
            item.get("cwes", [])
        )

        notes = (
            "Source: CISA KEV. "
            "CISA exploitation indicator: "
            f"{ransomware}. "
            "Independent corroboration: Not assessed. "
            "Local organizational exposure: Not assessed. "
            "This score evaluates source and metadata completeness, "
            "not proof of a data breach."
        )

        cursor.execute(
            """
            UPDATE intel_items

            SET
                known_ransomware_use = ?,
                due_date = ?,
                cwes = ?,
                risk_priority = ?,
                confidence_score = ?,
                confidence_level = ?,
                analysis_notes = ?,
                analyzed_at = ?

            WHERE id = ?
            """,

            (
                ransomware,
                due_date,
                cwes,
                priority,
                score,
                level,
                notes,
                analyzed_at,
                record_id
            )
        )

        analyzed += 1

        print(
            f"[+] Analyzed: {cve_id} "
            f"| Priority: {priority} "
            f"| Confidence: {score}/100 ({level})"
        )

    conn.commit()

    print("\n========== ANALYSIS SUMMARY ==========")

    print(f"Analyzed : {analyzed}")

    print(f"Skipped  : {skipped}")

    print("======================================")


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print("=" * 45)

    print("       DARKINTEL-CLI ANALYSIS ENGINE")

    print("=" * 45)

    conn = sqlite3.connect(DB_NAME)

    try:

        upgrade_analysis_schema(conn)

        metadata = fetch_cisa_metadata()

        analyze_records(conn, metadata)

        print("\n[+] Threat analysis completed.")

    except (
        sqlite3.Error,
        ValueError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as error:

        conn.rollback()

        print(f"\n[ERROR] {error}")

    finally:

        conn.close()


if __name__ == "__main__":

    main()

