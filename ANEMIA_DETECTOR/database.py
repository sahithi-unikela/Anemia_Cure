# database.py
import sqlitecloud
import os

# It’s safer to put your URL in an env var, e.g. SQLITE_CLOUD_URL
CLOUD_URL = os.getenv(
    "SQLITE_CLOUD_URL",
    "sqlitecloud://cwjtz4zfnz.g2.sqlite.cloud:8860/Anemia-data?apikey=M0OJ3xbTzB7HbBy7CgVAPfaQXC0fAHwCBIOG9XSbeag"
)

def get_conn():
    """Return a new SQLite Cloud connection."""
    return sqlitecloud.connect(CLOUD_URL)
