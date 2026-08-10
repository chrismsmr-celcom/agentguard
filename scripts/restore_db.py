#!/usr/bin/env python3
"""
Sauvegarde la base AgentGuard (spans + api_keys — perdre cette dernière table
signifie que plus aucun client hébergé ne peut s'authentifier).

Détecte automatiquement le moteur via AGENTGUARD_DB_TYPE, comme collector.py.

Postgres : pg_dump en format custom compressé (restaurable avec pg_restore,
           et avec une seule table si besoin — utile pour ne restaurer QUE
           api_keys sans toucher aux spans, par exemple).
SQLite    : API de backup sqlite3 (source.backup(dest)) — contrairement à un
           simple `cp`, ça reste cohérent même si le collector écrit pendant
           la sauvegarde (pas de fichier corrompu à moitié écrit).

Garde les N dernières sauvegardes (rotation), supprime les plus anciennes.

Usage :
    python scripts/backup_db.py
    python scripts/backup_db.py --keep 14        # changer la rétention
    python scripts/backup_db.py --dir /mnt/backups
"""
import argparse
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DB_TYPE = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
DB_SQLITE_PATH = os.environ.get("AGENTGUARD_DB_PATH", "/tmp/agentguard.db")


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def backup_postgres(backup_dir: Path) -> Path:
    if not DATABASE_URL:
        print("[backup] ERREUR: DATABASE_URL non défini alors que "
              "AGENTGUARD_DB_TYPE=postgres.", file=sys.stderr)
        sys.exit(1)
    out_file = backup_dir / f"agentguard_{timestamp()}.dump"
    result = subprocess.run(
        ["pg_dump", DATABASE_URL, "-F", "c", "-f", str(out_file)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[backup] ÉCHEC pg_dump: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return out_file


def backup_sqlite(backup_dir: Path) -> Path:
    if not os.path.exists(DB_SQLITE_PATH):
        print(f"[backup] ERREUR: {DB_SQLITE_PATH} introuvable.", file=sys.stderr)
        sys.exit(1)
    out_file = backup_dir / f"agentguard_{timestamp()}.db"
    # sqlite3 backup API — cohérent même avec des écritures concurrentes,
    # contrairement à une copie de fichier brute (shutil.copy) qui pourrait
    # capturer le fichier à moitié écrit et produire une sauvegarde corrompue.
    source = sqlite3.connect(DB_SQLITE_PATH)
    dest = sqlite3.connect(str(out_file))
    with dest:
        source.backup(dest)
    source.close()
    dest.close()
    return out_file


def rotate(backup_dir: Path, pattern: str, keep: int):
    files = sorted(backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        old.unlink()
        print(f"[backup] Rotation — supprimé : {old.name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="backups", help="Dossier de destination")
    parser.add_argument("--keep", type=int, default=7, help="Nombre de sauvegardes à garder")
    args = parser.parse_args()

    backup_dir = Path(args.dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    if DB_TYPE == "postgres" and DATABASE_URL:
        out_file = backup_postgres(backup_dir)
        rotate(backup_dir, "agentguard_*.dump", args.keep)
    else:
        out_file = backup_sqlite(backup_dir)
        rotate(backup_dir, "agentguard_*.db", args.keep)

    size_kb = out_file.stat().st_size / 1024
    print(f"[backup] ✅ Sauvegarde créée : {out_file} ({size_kb:.1f} Ko)")


if __name__ == "__main__":
    main()
