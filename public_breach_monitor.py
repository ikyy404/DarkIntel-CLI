
import json
import sqlite3
import urllib.request
import urllib.error

from datetime import datetime, timezone
from urllib.parse import urlsplit

DB_NAME = "darkintel.db"

API_URL = "https://haveibeenpwned.com/api/v3/breaches"
MAX_RESPONSE_SIZE = 5 * 1024 * 1024


def initialize_catalog():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS public_breach_catalog (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            breach_name TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            domain TEXT,
            breach_date TEXT,
            added_date TEXT,
            pwn_count INTEGER,
            data_classes TEXT,
            is_verified INTEGER,
            is_fabricated INTEGER,
            is_spam_list INTEGER,
            is_malware INTEGER,
            is_stealer_log INTEGER,
            fetched_at TEXT NOT NULL,
            source_name TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def fetch_public_catalog():
    request = urllib.request.Request(
        API_URL,
        headers={
            "User-Agent": "DarkIntel-CLI/1.0",
            "Accept": "application/json"
        }
    )

    with urllib.request.urlopen(
        request, timeout=20
    ) as response:

        final_url = urlsplit(response.geturl())

        if (
            final_url.scheme != "https"
            or final_url.hostname != "haveibeenpwned.com"
        ):
            raise ValueError("Unexpected API destination.")

        raw_data = response.read(MAX_RESPONSE_SIZE + 1)

    if len(raw_data) > MAX_RESPONSE_SIZE:
        raise ValueError("API response exceeds size limit.")

    data = json.loads(raw_data.decode("utf-8"))

    if not isinstance(data, list):
        raise ValueError("Unexpected API response format.")

    return data


def save_catalog(records):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    inserted = 0
    updated = 0
    skipped = 0

    fetched_at = datetime.now(
        timezone.utc
    ).isoformat()

    try:
        for record in records:

            if not isinstance(record, dict):
                skipped += 1
                continue

            name = record.get("Name")
            title = record.get("Title")

            if not isinstance(name, str) or not name:
                skipped += 1
                continue

            if not isinstance(title, str) or not title:
                skipped += 1
                continue

            data_classes = record.get("DataClasses", [])

            if not isinstance(data_classes, list):
                data_classes = []

            pwn_count = record.get("PwnCount")

            if not isinstance(pwn_count, int) or pwn_count < 0:
                pwn_count = None

            existing = cursor.execute(
                "SELECT 1 FROM public_breach_catalog "
                "WHERE breach_name = ?",
                (name,)
            ).fetchone()

            values = (
                name,
                title,
                record.get("Domain"),
                record.get("BreachDate"),
                record.get("AddedDate"),
                pwn_count,
                json.dumps(data_classes),
                int(bool(record.get("IsVerified", False))),
                int(bool(record.get("IsFabricated", False))),
                int(bool(record.get("IsSpamList", False))),
                int(bool(record.get("IsMalware", False))),
                int(bool(record.get("IsStealerLog", False))),
                fetched_at,
                "HIBP_PUBLIC_API"
            )

            cursor.execute("""
                INSERT INTO public_breach_catalog (
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
                    fetched_at,
                    source_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                ON CONFLICT(breach_name) DO UPDATE SET
                    title = excluded.title,
                    domain = excluded.domain,
                    breach_date = excluded.breach_date,
                    added_date = excluded.added_date,
                    pwn_count = excluded.pwn_count,
                    data_classes = excluded.data_classes,
                    is_verified = excluded.is_verified,
                    is_fabricated = excluded.is_fabricated,
                    is_spam_list = excluded.is_spam_list,
                    is_malware = excluded.is_malware,
                    is_stealer_log = excluded.is_stealer_log,
                    fetched_at = excluded.fetched_at,
                    source_name = excluded.source_name
            """, values)

            if existing:
                updated += 1
            else:
                inserted += 1

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return inserted, updated, skipped


def main():
    print("\n=== DARKINTEL PUBLIC BREACH MONITOR ===")

    initialize_catalog()
    print("[+] Local catalog database ready.")

    print("[*] Connecting to HIBP public API...")

    try:
        records = fetch_public_catalog()

        print("[+] HTTPS connection successful.")
        print(f"[+] Records received: {len(records)}")

        inserted, updated, skipped = save_catalog(records)

        print("\n[ DATABASE SYNC RESULTS ]")
        print(f"[+] New records: {inserted}")
        print(f"[+] Updated records: {updated}")
        print(f"[+] Skipped records: {skipped}")

        print("\n[+] Catalog synchronization completed.")
        print("[!] Public metadata only.")
        print("[!] No passwords or leaked credentials stored.")
        print("[!] This is not an account exposure check.")

    except urllib.error.HTTPError as error:
        print(f"[!] HTTP error: {error.code}")

        if error.code == 429:
            print("[!] API rate limit reached. Try again later.")

    except urllib.error.URLError:
        print("[!] Network connection failed.")

    except (ValueError, json.JSONDecodeError) as error:
        print(f"[!] Invalid API response: {error}")

    except TimeoutError:
        print("[!] API connection timed out.")

    except (OSError, sqlite3.Error) as error:
        print(f"[!] System or database error: {error}")


if __name__ == "__main__":
    main()

