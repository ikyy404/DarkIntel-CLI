import sqlite3
import hashlib
import json
from datetime import datetime, timezone

DB_NAME = "darkintel.db"


def initialize_exposure_table():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS domain_exposures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            source_name TEXT NOT NULL,
            exposure_date TEXT,
            exposure_status TEXT NOT NULL,
            verification_status TEXT DEFAULT 'Unreviewed',
            content_hash TEXT UNIQUE,
            checked_at TEXT NOT NULL
        )
    """)

    columns = [
        row[1] for row in
        cursor.execute(
            "PRAGMA table_info(domain_exposures)"
        ).fetchall()
    ]

    if "data_classification" not in columns:
        cursor.execute("""
            ALTER TABLE domain_exposures
            ADD COLUMN data_classification TEXT
            DEFAULT 'SIMULATED'
        """)

    conn.commit()
    conn.close()

    print("[+] Exposure database initialized.")


def insert_demo_record():
    domain = "example.test"
    source = "DarkIntel Synthetic Demo"
    status = "SIMULATED - NOT A REAL EXPOSURE"

    fingerprint = hashlib.sha256(
        f"{domain}|{source}|{status}".encode()
    ).hexdigest()

    checked_at = datetime.now(
        timezone.utc
    ).isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO domain_exposures (
            domain,
            source_name,
            exposure_date,
            exposure_status,
            verification_status,
            content_hash,
            checked_at,
            data_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        domain,
        source,
        None,
        status,
        "Unreviewed",
        fingerprint,
        checked_at,
        "SIMULATED"
    ))

    if cursor.rowcount == 1:
        print("[+] Synthetic demo record inserted.")
    else:
        print("[i] Demo record already exists.")

    conn.commit()
    conn.close()
def save_exposure_metadata(domain, record):
    source = "Have I Been Pwned Public Breach Catalog"

    breach_name = str(record[0] or "Unknown")
    title = str(record[1] or "Untitled")
    exposure_date = record[3]

    source_verified = bool(record[6])

    verification = (
        "Source Verified - Not Independently Reviewed"
        if source_verified
        else "Source Unverified"
    )

    status = "PUBLIC CATALOG MATCH - REVIEW REQUIRED"

    fingerprint_data = (
        f"{domain}|{source}|{breach_name}|"
        f"{title}|{exposure_date}"
    )

    fingerprint = hashlib.sha256(
        fingerprint_data.encode()
    ).hexdigest()

    checked_at = datetime.now(
        timezone.utc
    ).isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO domain_exposures (
            domain,
            source_name,
            exposure_date,
            exposure_status,
            verification_status,
            content_hash,
            checked_at,
            data_classification
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        domain,
        source,
        exposure_date,
        status,
        verification,
        fingerprint,
        checked_at,
        "PUBLIC_BREACH_METADATA"
    ))

    inserted = cursor.rowcount == 1

    conn.commit()
    conn.close()

    return inserted
def search_domain_metadata(domain):
    domain = domain.strip().lower().rstrip(".")

    if (
        not domain
        or "." not in domain
        or "://" in domain
        or "/" in domain
        or " " in domain
    ):
        print("[!] Invalid domain format.")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    records = cursor.execute("""
        SELECT
            breach_name,
            title,
            domain,
            breach_date,
            pwn_count,
            data_classes,
            is_verified,
            is_fabricated,
            is_malware,
            is_stealer_log
        FROM public_breach_catalog
        WHERE LOWER(domain) = ?
        ORDER BY breach_date DESC
        LIMIT 20
    """, (domain,)).fetchall()

    conn.close()

    print("\n=== PUBLIC BREACH METADATA ===")
    print(f"[*] Domain searched: {domain}")
    print(f"[*] Matching records: {len(records)}")

    if not records:
        print("[i] No matching catalog metadata found.")
        return
    saved_count = 0
    duplicate_count = 0

    for record in records:
        if save_exposure_metadata(domain, record):
            saved_count += 1
        else:
            duplicate_count += 1

    print(f"\n[+] New metadata records saved: {saved_count}")
    print(f"[i] Duplicate records skipped: {duplicate_count}")
    for index, item in enumerate(records, start=1):
        try:
            classes = json.loads(item[5] or "[]")
            if isinstance(classes, list):
                classes = ", ".join(str(x) for x in classes)
        except (TypeError, ValueError):
            classes = str(item[5] or "Not specified")

        print(f"\n[{index}] {item[0]}")
        print(f"    Title: {item[1]}")
        print(f"    Domain: {item[2]}")
        print(f"    Breach date: {item[3] or 'Unknown'}")
        print(f"    Reported accounts: {item[4] or 0}")
        print(f"    Data classes: {classes}")
        print(f"    Verified by source: {bool(item[6])}")
        print(f"    Fabricated flag: {bool(item[7])}")
        print(f"    Malware flag: {bool(item[8])}")
        print(f"    Stealer log flag: {bool(item[9])}")

    print("\n[!] Catalog metadata does not prove domain ownership")
    print("[!] or exposure of any specific account or organization.")
    print("[!] No credentials or passwords were accessed.")

if __name__ == "__main__":
    print("\n=== DARKINTEL EXPOSURE CHECKER ===")

    initialize_exposure_table()
    insert_demo_record()

    print("\n[1] Search public breach metadata")
    print("[2] Exit")

    choice = input("\nSelect option: ").strip()

    if choice == "1":
        domain = input(
            "Enter an owned or authorized domain: "
        )
        search_domain_metadata(domain)

    elif choice == "2":
        print("[+] Returning to terminal.")

    else:
        print("[!] Invalid option.")

    print("\n[!] No credentials or passwords were accessed.")

