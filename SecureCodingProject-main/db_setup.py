import mysql.connector

DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
}

DB_NAME = "com_ltd"


def exec_sql(cursor, sql: str):
    """Executes SQL and prints which statement is running (helps debug server drops)."""
    first_line = sql.strip().splitlines()[0].strip()
    print(f"Running: {first_line[:120]}...")
    cursor.execute(sql)


def initialize_database():
    print("Connecting to MySQL Server...")

    # 1) Connect to server (no DB selected) + create DB
    conn = mysql.connector.connect(**DB_CONFIG, use_pure=True)
    cursor = conn.cursor()

    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    print(f"Database '{DB_NAME}' created or exists.")

    cursor.close()
    conn.close()

    # 2) Connect with DB selected
    db_cfg = DB_CONFIG.copy()
    db_cfg["database"] = DB_NAME

    conn = mysql.connector.connect(**db_cfg, use_pure=True)
    cursor = conn.cursor()

    # Users table
    exec_sql(cursor, """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        salt VARCHAR(255) NOT NULL,
        login_attempts INT DEFAULT 0
    ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
    """)

    # Password history table (FK requires InnoDB)
    exec_sql(cursor, """
    CREATE TABLE IF NOT EXISTS password_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_password_history_user
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
    """)

    # Clients table:
    # - supports BOTH vulnerable & secure columns
    # - use TEXT for big fields to avoid row-size / storage issues in some XAMPP/MariaDB setups
    exec_sql(cursor, """
    CREATE TABLE IF NOT EXISTS clients (
        id INT AUTO_INCREMENT PRIMARY KEY,

        -- Vulnerable app fields
        client_name VARCHAR(255) NULL,
        description TEXT NULL,
        website_url TEXT NULL,

        -- Secure app fields
        first_name VARCHAR(255) NULL,
        last_name VARCHAR(255) NULL,
        phone VARCHAR(255) NULL,
        email VARCHAR(255) NULL,
        address VARCHAR(255) NULL
    ) ENGINE=InnoDB ROW_FORMAT=DYNAMIC
    """)

    # Insert default admin user
    import security_utils
    password_hash, salt = security_utils.hash_password("admin123")

    cursor.execute("""
        INSERT IGNORE INTO users (username, email, password_hash, salt, login_attempts)
        VALUES (%s, %s, %s, %s, %s)
    """, ("admin", "admin@com.ltd", password_hash, salt, 0))

    conn.commit()
    cursor.close()
    conn.close()

    print("Database initialization complete.")


if __name__ == "__main__":
    initialize_database()
