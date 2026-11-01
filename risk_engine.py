
import sqlite3

from datetime import datetime, timezone


DB_NAME = "darkintel.db"


def upgrade_schema(conn):
    """Add Smart Risk Scoring fields."""

    cursor = conn.cursor()

    existing = {
        row[1]
        for row in cursor.execute(
            "PRAGMA table_info(intel_items)"
        ).fetchall()
    }

    columns = [
        ("cvss_score", "REAL"),
        ("corroboration_status", "TEXT DEFAULT 'Not Assessed'"),
        ("smart_risk_score", "INTEGER DEFAULT 0"),
        ("smart_risk_level", "TEXT DEFAULT 'Unassessed'"),
        ("risk_assessment_status", "TEXT DEFAULT 'Provisional'"),
        ("risk_reason", "TEXT"),
        ("risk_scored_at", "TEXT")
    ]

    for name, definition in columns:
        if name not in existing:
            cursor.execute(
                f"ALTER TABLE intel_items ADD COLUMN "
                f"{name} {definition}"
            )
            print(f"[+] Added column: {name}")

    conn.commit()


def score_cvss(value):
    """Convert CVSS severity into weighted points."""

    if value is None:
        return 0

    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0

    if not 0 <= score <= 10:
        return 0

    if score >= 9.0:
        return 30
    elif score >= 7.0:
        return 22
    elif score >= 4.0:
        return 12
    elif score > 0:
        return 5

    return 0


def calculate_risk(record):
    """Calculate a transparent operational risk score."""

    score = 0
    reasons = []
    missing = []

    # 1. CVSS severity: maximum 30
    cvss_points = score_cvss(record["cvss_score"])
    score += cvss_points

    if record["cvss_score"] is None:
        missing.append("CVSS score unavailable")
    else:
        reasons.append(f"CVSS contribution: {cvss_points}/30")

    # 2. CISA KEV inclusion: maximum 30
    score += 30
    reasons.append("Listed in CISA KEV: 30/30")

    # 3. Known ransomware use: maximum 20
    ransomware = record["known_ransomware_use"]

    if ransomware == "Known":
        score += 20
        reasons.append("Known ransomware use: 20/20")
    elif ransomware == "Unknown":
        missing.append("Ransomware usage unknown")
    else:
        reasons.append("No known ransomware use reported: 0/20")

    # 4. Metadata completeness: maximum 10
    metadata_fields = [
        record["title"],
        record["description"],
        record["link"],
        record["source_date"],
        record["due_date"],
        record["cwes"]
    ]

    available = sum(
        1 for value in metadata_fields
        if value is not None and str(value).strip()
    )

    metadata_points = round(
        (available / len(metadata_fields)) * 10
    )

    score += metadata_points
    reasons.append(
        f"Metadata completeness: {metadata_points}/10"
    )

    # 5. Independent corroboration: maximum 10
    corroboration = record["corroboration_status"]

    if corroboration == "Confirmed":
        score += 10
        reasons.append("Independent corroboration: 10/10")
    else:
        missing.append("Independent corroboration not confirmed")

    # Final category
    score = min(score, 100)

    if score >= 75:
        level = "Critical"
    elif score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    assessment_status = (
        "Provisional" if missing else "Complete"
    )

    if missing:
        reasons.extend(
            f"Pending assessment: {item}"
            for item in missing
        )

    return (
        score,
        level,
        assessment_status,
        "; ".join(reasons)
    )


def analyze_risks(conn):
    """Calculate and save risk assessments."""

    cursor = conn.cursor()

    records = cursor.execute(
        """
        SELECT
            id,
            cvss_score,
            known_ransomware_use,
            title,
            description,
            link,
            source_date,
            due_date,
            cwes,
            corroboration_status
        FROM intel_items
        WHERE source_name = ?
        """,
        ("CISA KEV",)
    ).fetchall()

    scored_at = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    processed = 0

    for record in records:
        (
            record_id,
            cvss,
            ransomware,
            title,
            description,
            link,
            source_date,
            due_date,
            cwes,
            corroboration
        ) = record

        data = {
            "cvss_score": cvss,
            "known_ransomware_use": ransomware,
            "title": title,
            "description": description,
            "link": link,
            "source_date": source_date,
            "due_date": due_date,
            "cwes": cwes,
            "corroboration_status": corroboration
        }

        score, level, status, reason = calculate_risk(data)

        cursor.execute(
            """
            UPDATE intel_items
            SET
                smart_risk_score = ?,
                smart_risk_level = ?,
                risk_assessment_status = ?,
                risk_reason = ?,
                risk_scored_at = ?
            WHERE id = ?
            """,
            (
                score,
                level,
                status,
                reason,
                scored_at,
                record_id
            )
        )

        processed += 1

        print(
            f"[+] {record_id}: "
            f"{score}/100 ({level}) | {status}"
        )

    conn.commit()

    print("\n========== RISK SUMMARY ==========")
    print(f"Processed: {processed}")
    print("==================================")


def main():
    print("=" * 45)
    print("       DARKINTEL SMART RISK ENGINE")
    print("=" * 45)

    try:
        conn = sqlite3.connect(DB_NAME)

        try:
            upgrade_schema(conn)
            analyze_risks(conn)

            print("\n[+] Risk assessment completed.")

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

    except (sqlite3.Error, OSError, ValueError) as error:
        print(f"\n[ERROR] {error}")


if __name__ == "__main__":
    main()

