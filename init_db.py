
import sqlite3

# Database filename
DB_NAME = "darkintel.db"


def initialize_database():
    # Connect to SQLite database
    conn = sqlite3.connect(DB_NAME)

    # Create cursor to execute SQL commands
    cursor = conn.cursor()

    # Create breaches table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breaches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tanggal TEXT NOT NULL,
            nama_forum TEXT NOT NULL,
            judul_kebocoran TEXT NOT NULL,
            jumlah_user_terdampak INTEGER DEFAULT 0,
            status_analisis TEXT DEFAULT 'Pending'
        )
    """)

    # Save changes
    conn.commit()

    # Close database connection
    conn.close()

    print("[+] DarkIntel database initialized successfully!")


if __name__ == "__main__":
    initialize_database()

