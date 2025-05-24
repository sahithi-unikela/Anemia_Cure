# database.py
import sqlitecloud
import os

# It’s safer to put your URL in an env var, e.g. SQLITE_CLOUD_URL
CLOUD_URL = os.getenv(
    "SQLITE_CLOUD_URL",
    "sqlitecloud://colhzbgbnk.g4.sqlite.cloud:8860/users?apikey=CjSaBkPjHvx0ajgjCQorDZVUZfiLm9Kftyzv7Vw2U6c"
)

def get_conn():
    """Return a new SQLite Cloud connection."""
    return sqlitecloud.connect(CLOUD_URL)
