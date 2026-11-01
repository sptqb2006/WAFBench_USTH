#!/usr/bin/env python3
"""
Application Oracle for SQL Injection (Table 4.2)
Verifies whether an unauthorized session was issued into PostgreSQL app-db.
Author: Kieu Dang Vuong
"""

import os
import subprocess
import psycopg2

def check_sqli_backend_effect(db_host: str, correlation_id: str, submitted_user: str) -> dict:
    """
    Checks if a session was created in the sessions table for an unauthorized injection.
    Supports direct psycopg2 connection with fallback to docker exec for isolated networks.
    """
    row = None
    try:
        conn = psycopg2.connect(
            host=db_host,
            port=int(os.getenv("APP_DB_PORT", "5432")),
            dbname=os.getenv("APP_DB_NAME", "vulnerable_db"),
            user=os.getenv("APP_DB_USER", "app_user"),
            password=os.getenv("APP_DB_PASSWORD", "app_secret_pass"),
            connect_timeout=2
        )
        with conn.cursor() as cur:
            cur.execute("SELECT id, session_token, username FROM sessions ORDER BY id DESC LIMIT 1;")
            row = cur.fetchone()
        conn.close()
    except Exception:
        # Fallback to docker exec when app-db is isolated on backend-net
        try:
            cmd = [
                "docker", "exec", "wb-app-db",
                "psql", "-U", os.getenv("APP_DB_USER", "app_user"),
                "-d", os.getenv("APP_DB_NAME", "vulnerable_db"),
                "-t", "-A", "-F", "|",
                "-c", "SELECT id, session_token, username FROM sessions ORDER BY id DESC LIMIT 1;"
            ]
            out = subprocess.check_output(cmd, timeout=3).decode("utf-8").strip()
            if out:
                parts = out.split("|")
                if len(parts) >= 3:
                    row = (parts[0], parts[1], parts[2])
        except Exception as e:
            return {
                "backend_effect": False,
                "error": str(e),
                "observation": f"Database check failed: {e}"
            }

    if row:
        return {
            "backend_effect": True,
            "observation": f"Unauthorized session issued to user: {row[2]}",
            "session_token": row[1]
        }
    return {
        "backend_effect": False,
        "observation": "No session found in database"
    }
