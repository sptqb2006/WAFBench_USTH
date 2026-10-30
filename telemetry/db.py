import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection():
    return psycopg2.connect(
        host=os.getenv("EVENT_DB_HOST", "event-db"),
        port=int(os.getenv("EVENT_DB_PORT", "5432")),
        dbname=os.getenv("EVENT_DB_NAME", "wafbench_events"),
        user=os.getenv("EVENT_DB_USER", "telemetry_user"),
        password=os.getenv("EVENT_DB_PASSWORD", "telemetry_secret_pass"),
        cursor_factory=RealDictCursor
    )
