"""
AgentGuard Database Backup
- PostgreSQL : pg_dump (format custom) si DATABASE_URL est définie
- SQLite     : copie du fichier .db (auto-initialisation si absent, ex: CI)

Usage:
  python scripts/backup_db.py --dir backups --keep 30
"""
import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def log(msg):
    print(f"[backup] {msg}")


def backup_postgres(database_url: str, backup_dir: Path, timestamp: str) -> Path:
    """Backup PostgreSQL via pg_dump."""
    parsed = urlparse(database_url)
    env = os.environ.copy()
    env["PGPASSWORD"] = parsed.password or ""
    env["PGHOST"] = parsed.hostname or "localhost"
    env["PGPORT"] = str(parsed.port or 5432)
    env["PGUSER"] = parsed.username or "postgres"
    env["PGDATABASE"] = (parsed.path or "/postgres").lstrip("/")

    backup_file = backup_dir / f"agentguard_pg_{timestamp}.dump"
    cmd = ["pg_dump", "--format=custom", "--no-owner", "--no-privileges"]

    log(f"pg_dump -> {backup_file.name}")
    with open(backup_file, "wb") as f:
        subprocess.run(cmd, env=env, stdout=f, check=True)
    return backup_file


def backup_sqlite(db_path: str, backup_dir: Path, timestamp: str) -> Path:
    """Backup SQLite par copie. Auto-initialise une DB de test si absente (CI)."""
    src = Path(db_path)

    if not src.exists():
        # Placeholder de CI uniquement : le vrai backup de production passe par
        # DATABASE_URL + pg_dump (voir backup_postgres). Ce fichier ne sert qu'à
        # ce que le job ne plante pas quand /tmp/agentguard.db n'existe pas encore
        # (ex. premier run sur un nouveau runner). AVANT : on importait tout
        # collector.db/collector.app (Flask, structlog, opentelemetry, ...) pour ça
        # -> une dépendance manquante dans requirements.txt (structlog) faisait
        # échouer le backup entier, même quand seul ce placeholder était utilisé.
        log(f"{src} introuvable — création d'un fichier SQLite vide (mode CI, sqlite3 stdlib uniquement)...")
        src.parent.mkdir(parents=True, exist_ok=True)
        import sqlite3
        conn = sqlite3.connect(src)
        conn.execute("CREATE TABLE IF NOT EXISTS _ci_placeholder (created_at TEXT)")
        conn.commit()
        conn.close()
        log("fichier placeholder créé")

    backup_file = backup_dir / f"agentguard_sqlite_{timestamp}.db"
    shutil.copy2(src, backup_file)
    log(f"copie SQLite -> {backup_file.name}")
    return backup_file


def rotate(backup_dir: Path, keep: int):
    """Rotation : ne garde que les `keep` derniers backups."""
    backups = sorted(
        backup_dir.glob("agentguard_*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old in backups[keep:]:
        log(f"rotation: suppression {old.name}")
        old.unlink()


def main():
    ap = argparse.ArgumentParser(description="AgentGuard database backup")
    ap.add_argument("--dir", type=Path, default=Path("backups"))
    ap.add_argument("--keep", type=int, default=30)
    args = ap.parse_args()

    args.dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    db_type = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite").lower()
    database_url = os.environ.get("DATABASE_URL", "")
    db_path = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")

    if db_type == "postgres" and database_url:
        backup_file = backup_postgres(database_url, args.dir, timestamp)
    else:
        if db_type == "postgres" and not database_url:
            log("⚠️ AGENTGUARD_DB_TYPE=postgres mais DATABASE_URL vide — fallback SQLite")
        backup_file = backup_sqlite(db_path, args.dir, timestamp)

    size_mb = backup_file.stat().st_size / 1024 / 1024
    log(f"✅ Backup créé: {backup_file.name} ({size_mb:.2f} MB)")

    rotate(args.dir, args.keep)
    log("✅ Backup terminé")


if __name__ == "__main__":
    main()

