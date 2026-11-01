
import sqlite3
from datetime import datetime, timezone

DB_NAME = "darkintel.db"


# ==========================================
# DATABASE SCHEMA MIGRATION
# ==========================================

def upgrade_database(conn):

    cursor = conn.cursor()

    columns = {
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(breaches)"
        ).fetchall()
    }

    new_columns = [
        ("confidence_score", "INTEGER NOT NULL DEFAULT 0"),
        ("confidence_level", "TEXT NOT NULL DEFAULT 'Low'"),
        ("verification_status", "TEXT NOT NULL DEFAULT 'Unverified'"),
        ("is_simulated", "INTEGER NOT NULL DEFAULT 0"),
        ("evidence_note", "TEXT DEFAULT 'No evidence recorded'")
    ]

    for column_name, column_type in new_columns:

        if column_name not in columns:

            cursor.execute(
                f"ALTER TABLE breaches ADD COLUMN "
                f"{column_name} {column_type}"
            )

            print(f"[+] Added column: {column_name}")

    conn.commit()


# ==========================================
# CONFIDENCE SCORE ENGINE
# ==========================================

def calculate_confidence(
    source_score,
    sample_score,
    corroboration_score
):

    scores = [
        source_score,
        sample_score,
        corroboration_score
    ]

    if any(
        not isinstance(score, int) or isinstance(score, bool)
        for score in scores
    ):
        raise ValueError("Scores must be integers")

    if not (
        0 <= source_score <= 40
        and 0 <= sample_score <= 30
        and 0 <= corroboration_score <= 30
    ):
        raise ValueError("Score exceeds allowed weight")

    total = sum(scores)

    if total < 40:
        level = "Low"

    elif total < 70:
        level = "Medium"

    else:
        level = "High"

    return total, level


# ==========================================
# MOCK THREAT INTELLIGENCE DATA
# ==========================================

def generate_mock_data():

    current_date = datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d")

    mock_records = [

        {
            "date": current_date,
            "forum": "DarkForums",
            "title": "[SIMULATION] Example Database Exposure",
            "affected_users": 12000,
            "source_score": 5,
            "sample_score": 0,
            "corroboration_score": 0,
            "verification": "Unverified",
            "evidence": "Synthetic training record. No real breach evidence."
        },

        {
            "date": current_date,
            "forum": "pwnforums",
            "title": "[SIMULATION] Example Account Data Claim",
            "affected_users": 5000,
            "source_score": 5,
            "sample_score": 0,
            "corroboration_score": 0,
            "verification": "Unverified",
            "evidence": "Synthetic training record. No real breach evidence."
        },

        {
            "date": current_date,
            "forum": "Spear.cx",
            "title": "[SIMULATION] Example Customer Data Exposure",
            "affected_users": 8500,
            "source_score": 5,
            "sample_score": 0,
            "corroboration_score": 0,
            "verification": "Unverified",
            "evidence": "Synthetic training record. No real breach evidence."
        }

    ]

    return mock_records


# ==========================================
# INSERT DATA INTO SQLITE
# ==========================================

def insert_mock_data(conn, records):

    cursor = conn.cursor()

    for record in records:

        score, level = calculate_confidence(
            record["source_score"],
            record["sample_score"],
            record["corroboration_score"]
        )

        # Prevent duplicate records
        existing = cursor.execute(
            """
            SELECT id FROM breaches
            WHERE tanggal = ?
            AND nama_forum = ?
            AND judul_kebocoran = ?
            """,
            (
                record["date"],
                record["forum"],
                record["title"]
            )
        ).fetchone()

        if existing:
            print(
                f"[!] Already exists: {record['forum']}"
            )
            continue

        cursor.execute(
            """
            INSERT INTO breaches (
                tanggal,
                nama_forum,
                judul_kebocoran,
                jumlah_user_terdampak,
                status_analisis,
                confidence_score,
                confidence_level,
                verification_status,
                is_simulated,
                evidence_note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["date"],
                record["forum"],
                record["title"],
                record["affected_users"],
                "Pending",
                score,
                level,
                record["verification"],
                1,
                record["evidence"]
            )
        )

        print(
            f"[+] Inserted: {record['forum']} "
            f"| Confidence: {score}/100 ({level})"
        )

    conn.commit()


# ==========================================
# MAIN PROGRAM
# ==========================================

def main():

    print("=" * 45)
    print("       DARKINTEL-CLI DATA ENGINE")
    print("=" * 45)

    conn = sqlite3.connect(DB_NAME)

    try:

        upgrade_database(conn)

        records = generate_mock_data()

        insert_mock_data(conn, records)

        print("\n[+] Mock intelligence processing completed.")

    except (sqlite3.Error, ValueError) as error:

        print(f"[ERROR] {error}")

        conn.rollback()

    finally:

        conn.close()


if __name__ == "__main__":
    main()

