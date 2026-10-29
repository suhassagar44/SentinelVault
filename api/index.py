"""Vercel Serverless Function entrypoint for SentinelVault FastAPI Gateway."""

import sys
import os
from pathlib import Path

# Resolve repository paths
file_dir = Path(__file__).resolve().parent
root_path = file_dir.parent
backend_path = root_path / "backend"

candidate_paths = [
    backend_path,
    root_path,
    Path.cwd() / "backend",
    Path.cwd(),
    file_dir / "backend",
]
for cp in candidate_paths:
    if cp.exists() and str(cp) not in sys.path:
        sys.path.insert(0, str(cp))

# In serverless environments (e.g. Vercel / AWS Lambda), ensure writable /tmp directories
if os.getenv("VERCEL") or not os.access(str(backend_path), os.W_OK):
    os.environ.setdefault("HOTFIX_KEYS_DIR", "/tmp/keys")
    tmp_db = Path("/tmp/hotfix_mvp.db")
    
    # Locate candidate pre-seeded database
    candidate_dbs = [
        backend_path / "hotfix_mvp.db",
        root_path / "hotfix_mvp.db",
        Path.cwd() / "backend" / "hotfix_mvp.db",
        Path.cwd() / "hotfix_mvp.db",
    ]
    for sdb in candidate_dbs:
        if sdb.exists():
            if not tmp_db.exists():
                try:
                    import shutil
                    tmp_db.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(str(sdb), str(tmp_db))
                except Exception:
                    pass
            os.environ["HOTFIX_DB_PATH"] = str(tmp_db)
            break

# Locate configuration files
for cfg_candidate in [root_path / "config" / "app.yaml", backend_path / "config" / "app.yaml", Path.cwd() / "config" / "app.yaml"]:
    if cfg_candidate.exists():
        os.environ.setdefault("HOTFIX_CONFIG_PATH", str(cfg_candidate))
        break

for spec_candidate in [root_path / "config" / "spec.yaml", backend_path / "config" / "spec.yaml", Path.cwd() / "config" / "spec.yaml"]:
    if spec_candidate.exists():
        os.environ.setdefault("HOTFIX_SPEC_PATH", str(spec_candidate))
        break

from app.main import create_application

app = create_application()


