import os
from dotenv import load_dotenv

load_dotenv()


def _require(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return val


NEO4J_URI      = _require("NEO4J_URI")
NEO4J_USERNAME = _require("NEO4J_USERNAME")
NEO4J_PASSWORD = _require("NEO4J_PASSWORD")
ANTHROPIC_KEY  = _require("ANTHROPIC_API_KEY")

NEO4J_MCP_URL  = os.environ.get("NEO4J_MCP_URL",  "http://127.0.0.1:8787")
ROCKETRIDE_URL = os.environ.get("ROCKETRIDE_URL",  "http://127.0.0.1:3000")
