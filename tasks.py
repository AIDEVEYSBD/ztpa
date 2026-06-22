#!/usr/bin/env python3
"""ZeroTrust Policy Advisor - task runner.

One uniform entrypoint that works on Windows, macOS, Linux and WSL with only a
system Python on PATH.

    python tasks.py setup        create venv + install backend & frontend deps
    python tasks.py db           apply db/schema.sql + db/auth_schema.sql (psycopg)
    python tasks.py seed         write the simulated tool exports (data/mock/*.json)
    python tasks.py precompute    run the deterministic engine -> snapshot in Postgres
    python tasks.py precompute-ai cache ranked actions + change decisions
    python tasks.py demo         seed + precompute + precompute-ai (full snapshot)
    python tasks.py backend      run the FastAPI API on :8000
    python tasks.py frontend     run the Next.js dashboard on :3000
    python tasks.py dev          run backend + frontend together (Ctrl-C stops both)
    python tasks.py verify       run the engine self-check
    python tasks.py seed-scale N base demo + N synthetic assets
    python tasks.py admin EMAIL                  create an admin user
    python tasks.py set-password EMAIL PASSWORD  set a user's password
    python tasks.py send-reset EMAIL             email a set-password link
    python tasks.py stop         best-effort kill of the dev servers
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
VENV = BACKEND / ".venv"
IS_WIN = os.name == "nt"


# --- path helpers ----------------------------------------------------------
def venv_python() -> Path:
    """Return the venv interpreter, handling Windows (Scripts) vs POSIX (bin)."""
    return VENV / ("Scripts/python.exe" if IS_WIN else "bin/python")


def tool(name: str) -> str:
    """Resolve an external tool (npm/node) to its full path; error clearly if absent."""
    found = shutil.which(name)
    if not found:
        sys.exit(f"ERROR: '{name}' not found on PATH. Install it and retry.")
    return found


def run(cmd, cwd: Path | None = None, check: bool = True) -> int:
    """Run a command, streaming output. cmd is a list of args (no shell)."""
    printable = " ".join(str(c) for c in cmd)
    print(f"  $ {printable}" + (f"   (cwd={cwd})" if cwd else ""))
    proc = subprocess.run([str(c) for c in cmd], cwd=str(cwd) if cwd else None)
    if check and proc.returncode != 0:
        sys.exit(proc.returncode)
    return proc.returncode


def sync_frontend_env() -> None:
    """Next.js reads env from its own dir; mirror the root .env into frontend/.

    Symlinks need admin on Windows, so we copy instead and re-sync on every run
    that needs it — keeping a single source of truth at the repo root .env.
    """
    src = ROOT / ".env"
    if src.exists():
        shutil.copyfile(src, FRONTEND / ".env")


# --- commands --------------------------------------------------------------
def cmd_setup(_args):
    base_python = sys.executable  # whatever invoked us (3.11+ is fine)
    if not venv_python().exists():
        print("==> creating backend venv")
        run([base_python, "-m", "venv", str(VENV)])
    vpy = venv_python()
    run([vpy, "-m", "pip", "install", "-q", "-U", "pip"])
    run([vpy, "-m", "pip", "install", "-q", "-r", str(BACKEND / "requirements.txt")])
    print("==> installing frontend deps")
    run([tool("npm"), "install", "--no-audit", "--no-fund"], cwd=FRONTEND)
    env = ROOT / ".env"
    if not env.exists():
        shutil.copyfile(ROOT / ".env.example", env)
        print("==> created .env from .env.example")
    sync_frontend_env()
    print("\n==> setup done. Edit .env (DATABASE_URL + AUTH_SECRET required; "
          "ANTHROPIC_API_KEY/RESEND_API_KEY optional), then: python tasks.py db && python tasks.py demo")


def cmd_db(_args):
    vpy = venv_python()
    run([vpy, str(ROOT / "db" / "migrate.py"), str(ROOT / "db" / "schema.sql")])
    run([vpy, str(ROOT / "db" / "migrate.py"), str(ROOT / "db" / "auth_schema.sql")])


def _backend_script(name: str, *extra):
    run([venv_python(), str(BACKEND / "scripts" / name), *extra])


def cmd_seed(_args):       _backend_script("seed_demo.py")
def cmd_precompute(_args): _backend_script("precompute.py")
def cmd_verify(_args):     _backend_script("verify_engine.py")


def cmd_precompute_ai(args):
    _backend_script("precompute_ai.py", *args)  # e.g. --explanations


def cmd_seed_scale(args):
    if not args:
        sys.exit("usage: python tasks.py seed-scale N")
    _backend_script("seed_scale.py", args[0])


def cmd_demo(_args):
    cmd_seed(_args)
    cmd_precompute(_args)
    cmd_precompute_ai([])
    print("\n==> snapshot built + cached. Run 'python tasks.py dev'.")


def _uvicorn_cmd():
    return [venv_python(), "-m", "uvicorn", "app.main:app",
            "--host", "127.0.0.1", "--port", "8000", "--reload"]


def cmd_backend(_args):
    run(_uvicorn_cmd(), cwd=BACKEND)


def cmd_frontend(_args):
    sync_frontend_env()
    run([tool("npm"), "run", "dev"], cwd=FRONTEND)


def cmd_dev(_args):
    sync_frontend_env()
    print("starting backend (:8000) + frontend (:3000) — Ctrl-C stops both")
    backend = subprocess.Popen([str(c) for c in _uvicorn_cmd()], cwd=str(BACKEND))
    try:
        subprocess.run([tool("npm"), "run", "dev"], cwd=str(FRONTEND))
    except KeyboardInterrupt:
        pass
    finally:
        backend.terminate()
        try:
            backend.wait(timeout=10)
        except subprocess.TimeoutExpired:
            backend.kill()


def _node_script(name: str, *extra):
    sync_frontend_env()
    run([tool("node"), str(FRONTEND / "scripts" / name), *extra], cwd=FRONTEND)


def cmd_admin(args):
    if not args:
        sys.exit("usage: python tasks.py admin EMAIL")
    _node_script("create-admin.mjs", *args)


def cmd_set_password(args):
    if len(args) < 2:
        sys.exit("usage: python tasks.py set-password EMAIL PASSWORD")
    _node_script("create-admin.mjs", args[0], args[1])


def cmd_send_reset(args):
    if not args:
        sys.exit("usage: python tasks.py send-reset EMAIL")
    _node_script("send-reset.mjs", args[0])


def cmd_stop(_args):
    if IS_WIN:
        # /F force, /FI filter on command line; ignore "not found" exit codes.
        for pat in ("uvicorn app.main:app", "next dev"):
            subprocess.run(["taskkill", "/F", "/FI", f"WINDOWTITLE eq {pat}"], check=False)
        subprocess.run(["taskkill", "/F", "/IM", "node.exe"], check=False)
        print("note: on Windows, the surest stop is Ctrl-C in the `dev` window.")
    else:
        for pat in ("uvicorn app.main:app", "next dev"):
            subprocess.run(["pkill", "-f", pat], check=False)


def cmd_help(_args):
    print(__doc__)


COMMANDS = {
    "help": cmd_help,
    "setup": cmd_setup,
    "db": cmd_db,
    "seed": cmd_seed,
    "seed-scale": cmd_seed_scale,
    "precompute": cmd_precompute,
    "precompute-ai": cmd_precompute_ai,
    "demo": cmd_demo,
    "backend": cmd_backend,
    "frontend": cmd_frontend,
    "dev": cmd_dev,
    "verify": cmd_verify,
    "admin": cmd_admin,
    "set-password": cmd_set_password,
    "send-reset": cmd_send_reset,
    "stop": cmd_stop,
}


def main() -> None:
    args = sys.argv[1:]
    name = args[0] if args else "help"
    fn = COMMANDS.get(name)
    if not fn:
        print(f"unknown command: {name}\n")
        cmd_help(None)
        sys.exit(2)
    fn(args[1:])


if __name__ == "__main__":
    main()
