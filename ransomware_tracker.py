
import sqlite3
import urllib.request
import xml.etree.ElementTree as ET
import hashlib
import re

from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlparse


DB_NAME = "darkintel.db"

FEED_URL = (
    "https://www.cisa.gov/cybersecurity-advisories/"
    "cybersecurity-advisories.xml"
)

ALLOWED_HOSTS = {
    "www.cisa.gov",
    "cisa.gov"
}

MAX_RESPONSE_SIZE = 2 * 1024 * 1024

KEYWORDS = [
    "ransomware",
    "malware",
    "trojan",
    "botnet",
    "infostealer",
    "cryptojacking",
    "wiper malware",
    "malicious software"
]


def clean_text(value):
    if not value:
        return ""

    value = unescape(value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip()


def validate_url(url):
    parsed = urlparse(url)

    return (
        parsed.scheme == "https"
        and parsed.hostname in ALLOWED_HOSTS
    )


def create_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ransomware_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            title TEXT NOT NULL,
            link TEXT NOT NULL UNIQUE,
            published_date TEXT,
            description TEXT,
            threat_category TEXT,
            content_hash TEXT NOT NULL,
            collected_at TEXT NOT NULL
        )
        """
    )

    conn.commit()
    print("[+] Ransomware reports table ready.")


def fetch_feed():
    if not validate_url(FEED_URL):
        raise ValueError("Feed URL is not allowed.")

    request = urllib.request.Request(
        FEED_URL,
        headers={
            "User-Agent": "DarkIntel-CLI/1.0",
            "Accept": "application/rss+xml, application/xml"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=20
    ) as response:

        if response.status != 200:
            raise ValueError(
                f"Unexpected HTTP status: {response.status}"
            )

        content_type = response.headers.get(
            "Content-Type", ""
        ).lower()

        if "xml" not in content_type:
            raise ValueError("Unexpected feed content type.")

        data = response.read(MAX_RESPONSE_SIZE + 1)

    if len(data) > MAX_RESPONSE_SIZE:
        raise ValueError("Feed exceeds the size limit.")

    return data


def classify_article(title, description):
    text = f"{title} {description}".lower()

    matches = [
        keyword
        for keyword in KEYWORDS
        if keyword in text
    ]

    if not matches:
        return None

    if "ransomware" in matches:
        return "Ransomware"

    return "Malware"


def process_feed(conn, xml_data):
    root = ET.fromstring(xml_data)

    items = root.findall("./channel/item")

    cursor = conn.cursor()

    collected_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    inserted = 0
    duplicates = 0
    ignored = 0

    for item in items:
        title = clean_text(
            item.findtext("title")
        )

        link = (
            item.findtext("link") or ""
        ).strip()

        description = clean_text(
            item.findtext("description")
        )

        published = clean_text(
            item.findtext("pubDate")
        )

        if not title or not validate_url(link):
            ignored += 1
            continue

        category = classify_article(
            title,
            description
        )

        if category is None:
            ignored += 1
            continue

        fingerprint = hashlib.sha256(
            f"{title}|{link}|{description}".encode(
                "utf-8"
            )
        ).hexdigest()

        try:
            cursor.execute(
                """
                INSERT INTO ransomware_reports (
                    source_name,
                    title,
                    link,
                    published_date,
                    description,
                    threat_category,
                    content_hash,
                    collected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "CISA RSS",
                    title,
                    link,
                    published,
                    description[:5000],
                    category,
                    fingerprint,
                    collected_at
                )
            )

            inserted += 1

            print(
                f"[+] {category}: {title[:75]}"
            )

        except sqlite3.IntegrityError:
            duplicates += 1

    conn.commit()

    print("\n========== TRACKER SUMMARY ==========")
    print(f"RSS articles: {len(items)}")
    print(f"New reports: {inserted}")
    print(f"Duplicates: {duplicates}")
    print(f"Ignored articles: {ignored}")
    print("=====================================")


def main():
    print("=" * 48)
    print("      DARKINTEL RANSOMWARE & MALWARE TRACKER")
    print("=" * 48)

    conn = None

    try:
        conn = sqlite3.connect(DB_NAME)

        create_table(conn)

        print("[*] Fetching public CISA advisories...")

        xml_data = fetch_feed()

        print("[+] RSS feed retrieved successfully.")

        process_feed(conn, xml_data)

        print("\n[+] Tracker completed.")

    except (
        sqlite3.Error,
        OSError,
        ValueError,
        ET.ParseError
    ) as error:

        print(f"\n[ERROR] {error}")

    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    main()

