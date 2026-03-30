import os

from dotenv import load_dotenv

load_dotenv()


def get(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def require(key: str) -> str:
    val = get(key)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return val


# Keep module-level names for compatibility with existing imports and tests,
# but avoid failing at import time when local env vars have not been set yet.
NEO4J_URI = get("NEO4J_URI")
NEO4J_USERNAME = get("NEO4J_USERNAME")
NEO4J_PASSWORD = get("NEO4J_PASSWORD")
ANTHROPIC_KEY = get("ANTHROPIC_API_KEY")

_mcp_raw = get("NEO4J_MCP_URL", "http://127.0.0.1:8787")
NEO4J_MCP_URL = _mcp_raw if _mcp_raw.startswith("http") else f"http://{_mcp_raw}"
ROCKETRIDE_URL = get("ROCKETRIDE_URL", "http://127.0.0.1:3000")  # legacy (scripts)
ROCKETRIDE_URI = get("ROCKETRIDE_URI", "http://localhost:5565")   # SDK default
