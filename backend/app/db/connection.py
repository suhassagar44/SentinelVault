"""SQLite database connection and schema initialization for HOTFIX MVP."""

import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
import hashlib
import secrets

DB_PATH_ENV = os.getenv("HOTFIX_DB_PATH", "hotfix_mvp.db")


def get_db_path() -> Path:
    """Resolve database path relative to repository or backend directory."""
    env_path = os.getenv("HOTFIX_DB_PATH", "hotfix_mvp.db")
    p = Path(env_path)
    if p.is_absolute():
        return p
    
    backend_root = Path(__file__).resolve().parent.parent.parent
    repo_root = backend_root.parent
    candidates = [
        Path.cwd() / p,
        Path.cwd() / "backend" / p,
        backend_root / p,
        repo_root / p,
        repo_root / "backend" / p,
    ]
    for c in candidates:
        if c.exists():
            return c
    return backend_root / p


def get_connection() -> sqlite3.Connection:
    """Returns an active SQLite connection with row factory configured."""
    db_path = get_db_path()
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    # If the database directory is read-only (e.g. AWS Lambda / Vercel Serverless), fallback to /tmp
    if os.getenv("VERCEL") or (not os.access(str(db_path.parent), os.W_OK) and not str(db_path).startswith("/tmp")):
        tmp_db = Path("/tmp/hotfix_mvp.db")
        if not tmp_db.exists():
            backend_root = Path(__file__).resolve().parent.parent.parent
            repo_root = backend_root.parent
            seed_candidates = [
                db_path,
                backend_root / "hotfix_mvp.db",
                repo_root / "backend" / "hotfix_mvp.db",
                repo_root / "hotfix_mvp.db",
                Path.cwd() / "backend" / "hotfix_mvp.db",
            ]
            for sdb in seed_candidates:
                if sdb.exists():
                    import shutil
                    try:
                        tmp_db.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(str(sdb), str(tmp_db))
                        break
                    except Exception:
                        pass
        if tmp_db.exists():
            db_path = tmp_db

    conn = sqlite3.connect(
        str(db_path),
        timeout=30.0,
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a password against its PBKDF2 hash using constant-time comparison."""
    key, _ = hash_password(password, salt)
    return secrets.compare_digest(key, stored_hash)


# Precomputed fixed dummy hash/salt to prevent username-enumeration timing side-channels
_DUMMY_SALT = "00112233445566778899aabbccddeeff"
_DUMMY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def verify_dummy_password(password: str) -> bool:
    """Simulates password verification computation to prevent timing disclosure for nonexistent users."""
    verify_password(password, _DUMMY_HASH, _DUMMY_SALT)
    return False


def record_security_event_db(
    conn,
    event_type: str,
    outcome: str,
    actor: Optional[str] = None,
    source_ip: Optional[str] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    details: Optional[str] = None
) -> str:
    """Records an immutable security audit event into the security_events table."""
    event_id = f"EVT-{secrets.token_hex(12)}"
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    INSERT INTO security_events (
        event_id, event_type, actor, source_ip, resource, action, outcome, details, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (event_id, event_type, actor or "anonymous", source_ip or "unknown", resource, action, outcome, details, now_iso))

    try:
        from app.services.incident_service import evaluate_detection_rules
        evaluate_detection_rules(
            event_type=event_type,
            actor=actor or "anonymous",
            outcome=outcome,
            details=details or "",
            resource=resource or "gateway",
            conn=conn
        )
    except Exception:
        pass  # Never allow detection rule evaluation to break security event persistence

    return event_id


def init_database() -> None:
    """Creates the SQLite tables and seeds the demo environment if not already initialized."""
    conn = get_connection()
    try:
        # Execute schema definition via executescript
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            user_id TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            last_password_change TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            mfa_secret TEXT,
            mfa_recovery_codes_hash TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_accessed_at TEXT,
            is_revoked INTEGER NOT NULL DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            source_ip TEXT,
            resource TEXT,
            action TEXT,
            outcome TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_security_events_actor ON security_events(actor);

        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            window_start INTEGER NOT NULL,
            request_count INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS budget_ledger (
            dataset_id TEXT PRIMARY KEY,
            cap_micro_epsilon INTEGER NOT NULL,
            spent_micro_epsilon INTEGER NOT NULL DEFAULT 0,
            remaining_micro_epsilon INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS query_releases (
            release_id TEXT PRIMARY KEY,
            idempotency_key TEXT UNIQUE,
            dataset_id TEXT NOT NULL,
            query_fingerprint TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            epsilon_micro INTEGER NOT NULL,
            raw_count_internal INTEGER NOT NULL,
            noisy_count INTEGER NOT NULL,
            mechanism TEXT NOT NULL,
            user_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            is_cached_release INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_releases_cache_key ON query_releases(cache_key);

        CREATE TABLE IF NOT EXISTS privacy_receipts (
            receipt_id TEXT PRIMARY KEY,
            release_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            dataset_id TEXT NOT NULL,
            dataset_version TEXT NOT NULL,
            query_fingerprint TEXT NOT NULL,
            query_description TEXT NOT NULL,
            mechanism TEXT NOT NULL,
            epsilon_spent REAL NOT NULL,
            cumulative_epsilon REAL NOT NULL,
            remaining_budget REAL NOT NULL,
            policy_check_status TEXT NOT NULL,
            audit_entry_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (release_id) REFERENCES query_releases(release_id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            actor TEXT NOT NULL,
            dataset_scope TEXT NOT NULL,
            query_fingerprint TEXT NOT NULL,
            privacy_expenditure_micro INTEGER NOT NULL,
            cumulative_expenditure_micro INTEGER NOT NULL,
            mechanism TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_alerts (
            alert_id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            actor TEXT,
            resource TEXT,
            details TEXT,
            evidence_json TEXT,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            resolved_by TEXT,
            resolved_at TEXT,
            resolution_notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
        CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);

        CREATE TABLE IF NOT EXISTS incident_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            current_state TEXT NOT NULL DEFAULT 'NORMAL',
            trigger_source TEXT NOT NULL DEFAULT 'SYSTEM_BOOT',
            reason TEXT NOT NULL DEFAULT 'Standard zero-trust gateway operations active.',
            updated_by TEXT NOT NULL DEFAULT 'system',
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incident_log (
            log_id TEXT PRIMARY KEY,
            prev_state TEXT NOT NULL,
            new_state TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """)

        # Migration support: Check and add missing columns to privacy_receipts
        receipt_cols = {row["name"] for row in conn.execute("PRAGMA table_info(privacy_receipts)").fetchall()}
        if "receipt_hash" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN receipt_hash TEXT DEFAULT ''")
        if "key_id" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN key_id TEXT NOT NULL DEFAULT 'ED25519-ENCLAVE-2026-V1'")
        if "schema_version" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0.0'")
        if "is_revoked" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN is_revoked INTEGER NOT NULL DEFAULT 0")
        if "revoked_reason" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN revoked_reason TEXT")
        if "revoked_at" not in receipt_cols:
            conn.execute("ALTER TABLE privacy_receipts ADD COLUMN revoked_at TEXT")

        # Migration support: Check and add missing columns to users
        user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "user_id" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN user_id TEXT NOT NULL DEFAULT ''")
        if "status" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE'")
        if "last_login_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        if "last_password_change" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_password_change TEXT")
        if "mfa_enabled" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0")
        if "mfa_secret" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
        if "mfa_recovery_codes_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN mfa_recovery_codes_hash TEXT")

        # Migration support: Check and add missing columns to sessions
        sess_cols = {row["name"] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        if "last_accessed_at" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN last_accessed_at TEXT")
        if "is_revoked" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN is_revoked INTEGER NOT NULL DEFAULT 0")
        if "ip_address" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN ip_address TEXT")
        if "user_agent" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN user_agent TEXT")

        # Seed default budget ledgers (5.0 Epsilon = 5,000,000 micro-epsilon)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
        INSERT OR IGNORE INTO budget_ledger (dataset_id, cap_micro_epsilon, spent_micro_epsilon, remaining_micro_epsilon, updated_at)
        VALUES 
            ('health', 5000000, 0, 5000000, ?),
            ('financial', 5000000, 0, 5000000, ?);
        """, (now_iso, now_iso))

        # Seed initial incident response state (NORMAL)
        conn.execute("""
        INSERT OR IGNORE INTO incident_state (id, current_state, trigger_source, reason, updated_by, updated_at)
        VALUES (1, 'NORMAL', 'SYSTEM_BOOT', 'Standard zero-trust gateway operations active.', 'system', ?);
        """, (now_iso,))

        # Seed demo users if not present
        demo_users = [
            ("analyst_user", "USR-analyst-001", os.getenv("DEMO_ANALYST_PASSWORD", "AnalystPass2026!"), "analyst"),
            ("steward_user", "USR-steward-001", os.getenv("DEMO_STEWARD_PASSWORD", "StewardPass2026!"), "data_steward"),
            ("auditor_user", "USR-auditor-001", os.getenv("DEMO_AUDITOR_PASSWORD", "AuditorPass2026!"), "auditor"),
            ("admin_user", "USR-admin-001", os.getenv("DEMO_ADMIN_PASSWORD", "AdminPass2026!"), "admin"),
        ]
        for username, user_id, pwd, role in demo_users:
            existing = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
            if not existing:
                h, salt = hash_password(pwd)
                conn.execute("""
                INSERT INTO users (username, user_id, password_hash, salt, role, status, failed_attempts, locked_until, created_at, last_password_change)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE', 0, NULL, ?, ?);
                """, (username, user_id, h, salt, role, now_iso, now_iso))
            else:
                # Ensure user_id is populated
                conn.execute("UPDATE users SET user_id = ? WHERE username = ? AND (user_id IS NULL OR user_id = '')", (user_id, username))
        conn.commit()
    finally:
        conn.close()
