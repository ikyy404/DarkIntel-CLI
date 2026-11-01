import sqlite3
import subprocess
import sys
import os

from pathlib import Path


DB_NAME = "darkintel.db"

# Terminal colors
RED = "\033[91m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def color(text, shade):
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        return str(text)
    return f"{shade}{text}{RESET}"


def line():
    print(color("═" * 48, CYAN))


def print_banner():
    print()
    line()

    print(color(
        r"""
  ____   ____  ____  _  __
 |  _ \ / __ \|  _ \| |/ /
 | | | | |  | | |_) | ' /
 | |_| | |__| |  _ <| . \
 |____/ \____/|_| \_\_|\_\
        """,
        RED
    ))

    print(color(
        "       CYBER THREAT INTELLIGENCE CLI",
        CYAN
    ))

    print(color(
        "              VERSION 1.0",
        WHITE
    ))

    line()

    print(color(
        "  [ SYSTEM STATUS ]",
        GREEN + BOLD
    ))

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        total = cursor.execute(
            "SELECT COUNT(*) FROM intel_items"
        ).fetchone()[0]

        conn.close()

        print(f"  Database       : {color('CONNECTED', GREEN)}")
        print(f"  Intelligence   : {color(total, CYAN)} records")
        print(f"  Engine         : {color('READY', GREEN)}")

    except sqlite3.Error:
        print(f"  Database       : {color('ERROR', RED)}")
        print(f"  Engine         : {color('UNAVAILABLE', RED)}")

    line()


def get_connection():
    return sqlite3.connect(DB_NAME)


def intelligence_overview():
    print()
    print(color("[ INTELLIGENCE OVERVIEW ]", CYAN + BOLD))

    try:
        conn = get_connection()
        cursor = conn.cursor()

        total = cursor.execute(
            "SELECT COUNT(*) FROM intel_items"
        ).fetchone()[0]

        print(f"\n  Total Records: {color(total, GREEN)}")

        queries = [
            (
                "Risk Priority",
                "SELECT risk_priority, COUNT(*) "
                "FROM intel_items GROUP BY risk_priority"
            ),
            (
                "Confidence",
                "SELECT confidence_level, COUNT(*) "
                "FROM intel_items GROUP BY confidence_level"
            ),
            (
                "Verification",
                "SELECT verification_status, COUNT(*) "
                "FROM intel_items GROUP BY verification_status"
            )
        ]

        for title, query in queries:
            print(color(f"\n  {title}:", YELLOW))

            for name, count in cursor.execute(query).fetchall():
                print(f"    {name}: {count}")

        conn.close()

    except sqlite3.Error as error:
        print(color(f"[DATABASE ERROR] {error}", RED))


def browse_intelligence():
    print()
    print(color("[ INTELLIGENCE RECORDS ]", CYAN + BOLD))

    try:
        conn = get_connection()
        cursor = conn.cursor()

        records = cursor.execute(
            """
            SELECT item_key, risk_priority,
                   confidence_score, verification_status
            FROM intel_items
            ORDER BY source_date DESC
            LIMIT 20
            """
        ).fetchall()

        if not records:
            print(color("[!] No records found.", YELLOW))

        for cve, priority, score, status in records:
            print()
            print(color(f"  {cve}", CYAN + BOLD))
            print(f"  Priority     : {priority}")
            print(f"  Confidence   : {score}/100")
            print(f"  Verification : {status}")
            print(color("  " + "-" * 38, GRAY))

        conn.close()

    except sqlite3.Error as error:
        print(color(f"[DATABASE ERROR] {error}", RED))


def run_script(script_name):
    script_path = Path(script_name)

    if not script_path.is_file():
        print(color(
            f"[!] Script not found: {script_name}",
            RED
        ))
        return

    print()
    print(color(
        f"[+] Launching {script_name}...",
        GREEN
    ))

    # Use virtual environment for PDF exporter
    if script_name == "pdf_exporter.py":
        venv_python = Path(".venv/bin/python")

        if not venv_python.is_file():
            print(color(
                "[!] Virtual environment Python not found.",
                RED
            ))
            return

        python_executable = str(venv_python)
    else:
        python_executable = sys.executable

    try:
        subprocess.run(
            [python_executable, str(script_path)],
            check=False
        )

    except OSError as error:
        print(color(f"[EXECUTION ERROR] {error}", RED))

def show_menu():
    print_banner()

    print(color("\n  [ MAIN MENU ]", YELLOW + BOLD))
    menu = [
        ("1", "Intelligence Overview"),
        ("2", "Browse Intelligence Records"),
        ("3", "Run Threat Monitoring"),
        ("4", "Run Threat Analysis"),
        ("5", "Generate CTI Report"),
        ("6", "Export PDF Report"),
        ("7", "Run Exposure Checker"),
        ("8", "Run Public Breach Monitor"),
        ("9", "Exit")
    ]
    for number, description in menu:
        print(
            f"  {color(f'[{number}]', RED + BOLD)} "
            f"{color(description, WHITE)}"
        )

    line()
def main():
    while True:
        show_menu()

        choice = input(
            color("\n  darkintel > ", GREEN + BOLD)
        ).strip()

        if choice == "1":
            intelligence_overview()

        elif choice == "2":
            browse_intelligence()

        elif choice == "3":
            run_script("monitor.py")

        elif choice == "4":
            run_script("analyze_intel.py")

        elif choice == "5":
            run_script("report_generator.py")

        elif choice == "6":
            run_script("pdf_exporter.py")

        elif choice == "7":
            run_script("exposure_checker.py")

        elif choice == "8":
            run_script("public_breach_monitor.py")

        elif choice == "9":
            print(color(
                "\n[+] DarkIntel-CLI shutdown complete.",
                GREEN
            ))
            break
        else:
            print(color(
                "\n[!] Invalid menu option.",
                RED
            ))

        input(color(
            "\nPress Enter to continue...",
            GRAY
        ))

if __name__ == "__main__":
    main()
