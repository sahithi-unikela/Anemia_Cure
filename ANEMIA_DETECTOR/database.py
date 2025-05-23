# database.py
import sqlitecloud
import os

# It’s safer to put your URL in an env var, e.g. SQLITE_CLOUD_URL
CLOUD_URL = os.getenv(
    "SQLITE_CLOUD_URL",
    "sqlitecloud://co6leh6ahz.g5.sqlite.cloud:8860/Users?apikey=Z8SHQNW04obXKXDaHuLDDbWQCZ5KEwLJq0pyQajbdRg"
)

def get_conn():
    """Return a new SQLite Cloud connection."""
    return sqlitecloud.connect(CLOUD_URL)
