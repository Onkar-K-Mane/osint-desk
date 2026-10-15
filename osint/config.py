"""Runtime configuration. Keys live in an env file, never in SQLite."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from dotenv import load_dotenv

APP_NAME = "OSINT Desk"
APP_VERSION = "0.5.0"

# Preview / Colab must bind all interfaces. Local lab use can set OSINT_HOST=127.0.0.1.
DEFAULT_HOST = os.environ.get("OSINT_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("OSINT_PORT", "8080"))

_ROOT = Path(__file__).resolve().parent.parent


def _default_data_dir() -> Path:
    env = os.environ.get("OSINT_DATA_DIR")
    if env:
        return Path(env).expanduser().resolve()
    # Colab
    if Path("/content").is_dir() and os.environ.get("COLAB_RELEASE_TAG"):
        return Path("/content/osint-desk-data")
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "osint-desk"
    return _ROOT / "data" / "app"


DATA_DIR = _default_data_dir()
SOURCES_PATH = Path(os.environ.get("OSINT_SOURCES", _ROOT / "sources.yaml"))
PACKAGE_DATA = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "osint.sqlite3"
SECRETS_PATH = DATA_DIR / "secrets.env"
SESSION_SECRET_PATH = DATA_DIR / "session.secret"

# Host header policy. Relaxed when bound on all interfaces (preview / Colab).
STRICT_HOSTS = os.environ.get("OSINT_STRICT_HOSTS", "0") in {"1", "true", "yes"}


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


def load_secrets() -> None:
    """Load keys from the per-user secrets file, then process env."""
    ensure_data_dir()
    if SECRETS_PATH.is_file():
        load_dotenv(SECRETS_PATH, override=False)
    env_file = _ROOT / ".env"
    if env_file.is_file():
        load_dotenv(env_file, override=False)


def session_secret() -> str:
    ensure_data_dir()
    if SESSION_SECRET_PATH.is_file():
        return SESSION_SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = os.urandom(32).hex()
    SESSION_SECRET_PATH.write_text(secret, encoding="utf-8")
    try:
        os.chmod(SESSION_SECRET_PATH, 0o600)
    except OSError:
        pass
    return secret


def read_secrets_map() -> dict[str, str]:
    if not SECRETS_PATH.is_file():
        return {}
    out: dict[str, str] = {}
    for line in SECRETS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_secret(key_env: str, value: str) -> None:
    """Atomically update secrets.env. Never logs the value."""
    if not key_env.isidentifier() or not key_env.isupper() and not all(
        c.isupper() or c.isdigit() or c == "_" for c in key_env
    ):
        # still allow typical ENV_NAMES
        if not all(c.isalnum() or c == "_" for c in key_env):
            raise ValueError("invalid key name")
    ensure_data_dir()
    mapping = read_secrets_map()
    value = value.strip()
    if value:
        mapping[key_env] = value
        os.environ[key_env] = value
    else:
        mapping.pop(key_env, None)
        os.environ.pop(key_env, None)
    lines = ["# OSINT Desk secrets — do not commit this file\n"]
    for k in sorted(mapping):
        v = mapping[k].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{k}="{v}"\n')
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, prefix=".secrets.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        os.replace(tmp, SECRETS_PATH)
        try:
            os.chmod(SECRETS_PATH, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def has_key(key_env: str | None) -> bool:
    if not key_env:
        return True
    val = os.environ.get(key_env, "")
    return bool(val.strip())


DEFAULT_EXPLAIN_PROMPT = (
    "You are an OSINT analyst assistant talking to a SOC analyst. "
    "Explain the supplied source data in plain English. Say what each important field means, "
    "what is actionable, and what is missing or ambiguous. Do not invent detections, scores, or context "
    "that are not in the data. Attribute every claim to the source that produced it."
)


def ai_prefs_path() -> Path:
    return DATA_DIR / "ai.json"


def load_ai_prefs() -> dict:
    path = ai_prefs_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_ai_prefs(prefs: dict) -> None:
    ensure_data_dir()
    path = ai_prefs_path()
    payload = json.dumps(prefs, indent=2)
    fd, tmp = tempfile.mkstemp(dir=DATA_DIR, prefix=".ai.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, path)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def ai_settings() -> dict[str, str | None]:
    """OpenAI-compatible backend. Prefs file overrides env. No silent fallback between backends."""
    prefs = load_ai_prefs()
    base = str(prefs.get("base_url") or os.environ.get("AI_BASE_URL") or "http://127.0.0.1:11434/v1").rstrip("/")
    model = (
        str(prefs.get("model") or "").strip()
        or os.environ.get("AI_MODEL", "").strip()
        or os.environ.get("OLLAMA_MODEL", "").strip()
        or "llama3.1"
    )
    key = os.environ.get("AI_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("XAI_API_KEY") or ""
    prompt = str(prefs.get("system_prompt") or os.environ.get("AI_SYSTEM_PROMPT") or "").strip() or DEFAULT_EXPLAIN_PROMPT
    temperature = str(prefs.get("temperature") if prefs.get("temperature") not in (None, "") else os.environ.get("AI_TEMPERATURE", "0.2"))
    max_tokens = str(prefs.get("max_tokens") if prefs.get("max_tokens") not in (None, "") else os.environ.get("AI_MAX_TOKENS", "700"))
    local = "127.0.0.1" in base or "localhost" in base
    label = os.environ.get("AI_LABEL") or (("Local: " if local else "Cloud: ") + model)
    return {
        "base_url": base,
        "model": model,
        "api_key": key or None,
        "label": label,
        "local": "1" if local else "0",
        "system_prompt": prompt,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }


def public_ai_settings() -> dict:
    s = ai_settings()
    return {
        "base_url": s["base_url"],
        "model": s["model"],
        "label": s["label"],
        "local": s["local"] == "1",
        "has_key": bool(s["api_key"]),
        "system_prompt": s["system_prompt"],
        "temperature": s["temperature"],
        "max_tokens": s["max_tokens"],
        "default_prompt": DEFAULT_EXPLAIN_PROMPT,
    }

