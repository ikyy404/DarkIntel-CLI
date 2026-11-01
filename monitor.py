
import json
import sqlite3
import hashlib

from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from urllib.error import URLError, HTTPError
import re


# ==========================================
# CONFIGURATION
# ==========================================

DB_NAME = "darkintel.db"

FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CATALOG_URL = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)

ALLOWED_HOST = "www.cisa.gov"

MAX_RESPONSE_SIZE = 10 * 1024 * 1024

MAX_RECORDS = 20


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def initialize_monitor_database(conn):

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intel_items (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source_name TEXT NOT NULL,

            item_key TEXT NOT NULL UNIQUE,

            title TEXT NOT NULL,

            link TEXT NOT NULL,

            source_date TEXT,

            description TEXT,

            content_hash TEXT NOT NULL UNIQUE,

            collected_at TEXT NOT NULL,

            verification_status TEXT DEFAULT 'Unreviewed',

            is_simulated INTEGER DEFAULT 0
        )
    """)

    conn.commit()

    print("[+] Intelligence database ready.")


# ==========================================
# FETCH PUBLIC JSON FEED
# ==========================================

def fetch_feed():

    parsed_url = urlparse(FEED_URL)

    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != ALLOWED_HOST
    ):
        raise ValueError("Feed URL is not allowlisted.")

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

        raise ValueError("Feed response exceeds size limit.")

    data = json.loads(raw_data.decode("utf-8"))

    if not isinstance(data.get("vulnerabilities"), list):

        raise ValueError("Unexpected JSON feed structure.")

    print("[+] Public feed downloaded successfully.")

    return data["vulnerabilities"]


# ==========================================
# NORMALIZE INTELLIGENCE DATA
# ==========================================

def normalize_records(records):

    normalized = []

    for item in records:

        cve_id = item.get("cveID", "")

        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue

        vendor = item.get("vendorProject", "Unknown")

        product = item.get("product", "Unknown")

        name = item.get(
            "vulnerabilityName",
            "Unnamed vulnerability"
        )

        description = item.get(
            "shortDescription",
            "No description available."
        )

        action = item.get(
            "requiredAction",
            "Consult vendor guidance."
        )

        title = f"{cve_id} - {name}"

        full_description = (
            f"Vendor: {vendor}\n"
            f"Product: {product}\n"
            f"Description: {description}\n"
            f"Required Action: {action}"
        )

        normalized.append({

            "item_key": cve_id,

            "title": title,

            "link": CATALOG_URL,

            "source_date": item.get("dateAdded", ""),

            "description": full_description

        })

    normalized.sort(
        key=lambda x: x["source_date"],
        reverse=True
    )

    return normalized[:MAX_RECORDS]


# ==========================================
# DEDUPLICATION AND DATABASE INSERTION
# ==========================================

def store_records(conn, records):

    cursor = conn.cursor()

    inserted = 0

    duplicates = 0

    collected_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    for record in records:

        unique_string = (
            "CISA-KEV:" + record["item_key"]
        )

        content_hash = hashlib.sha256(
            unique_string.encode("utf-8")
        ).hexdigest()

        cursor.execute(
            """
            INSERT OR IGNORE INTO intel_items (

                source_name,
                item_key,
                title,
                link,
                source_date,
                description,
                content_hash,
                collected_at,
                verification_status,
                is_simulated

            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,

            (
                "CISA KEV",
                record["item_key"],
                record["title"],
                record["link"],
                record["source_date"],
                record["description"],
                content_hash,
                collected_at,
                "Unreviewed",
                0
            )
        )

        if cursor.rowcount == 1:

            inserted += 1

            print(
                f"[+] New intelligence: "
                f"{record['item_key']}"
            )

        else:

            duplicates += 1

    conn.commit()

    print("\n========== COLLECTION SUMMARY ==========")

    print(f"New records : {inserted}")

    print(f"Duplicates  : {duplicates}")

    print("=========================================")


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print("=" * 45)

    print("       DARKINTEL-CLI MONITOR ENGINE")

    print("=" * 45)

    conn = sqlite3.connect(DB_NAME)

    try:

        initialize_monitor_database(conn)

        raw_records = fetch_feed()

        records = normalize_records(raw_records)

        print(
            f"[+] Normalized records: {len(records)}"
        )

        store_records(conn, records)

        print("\n[+] Monitoring completed successfully.")

    except (
        sqlite3.Error,
        ValueError,
        URLError,
        HTTPError,
        TimeoutError,
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as error:

        conn.rollback()

        print(f"\n[ERROR] {error}")

    finally:

        conn.close()


if __name__ == "__main__":

    main()

