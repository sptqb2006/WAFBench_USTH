#!/usr/bin/env python3
"""
Application Oracle for SQL Injection (Table 4.2)
Verifies whether an unauthorized session was issued into PostgreSQL app-db.
app-db sits on the isolated backend network, so it is queried through docker exec.
Author: Kieu Dang Vuong
"""

import os

from manager import docker_exec

DB_CONTAINER = os.getenv("APP_DB_CONTAINER", "wb-app-db")
DB_NAME = os.getenv("APP_DB_NAME", "vulnerable_db")
DB_USER = os.getenv("APP_DB_USER", "app_user")


def run_sql(sql: str) -> list:
    """Runs a query with psql inside app-db. Returns rows as lists of strings."""
    rc, out, err = docker_exec(DB_CONTAINER, ["psql", "-U", DB_USER, "-d", DB_NAME, "-t", "-A", "-F", "\t", "-c", sql])
    if rc != 0:
        raise RuntimeError((err or out).strip() or f"psql exited {rc}")
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def get_fixture_counts() -> dict:
    row = run_sql(
        "SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM articles), (SELECT count(*) FROM sessions);"
    )[0]
    return {"users": int(row[0]), "articles": int(row[1]), "sessions": int(row[2])}


def check_sqli_backend_effect(submitted_user: str) -> dict:
    """
    The fixture starts with no sessions, so every session row was issued by this request.
    Effect = a session for a user other than the one submitted (e.g. "admin'-- " -> admin).
    A normal login (alice -> alice) is not an effect.
    """
    try:
        rows = run_sql("SELECT username FROM sessions ORDER BY id;")
    except Exception as e:
        return {"backend_effect": False, "error": str(e), "observation": f"Database check failed: {e}"}

    issued = [r[0] for r in rows]
    foreign = [u for u in issued if u != submitted_user]
    if foreign:
        return {"backend_effect": True, "observation": f"Unauthorized session issued to user: {foreign[0]}"}
    if issued:
        return {"backend_effect": False, "observation": f"Legitimate session for submitted user: {submitted_user}"}
    return {"backend_effect": False, "observation": "No session found in database"}
