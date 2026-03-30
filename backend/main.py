"""
main.py — Cerberus FastAPI backend entry point.

Start with:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import neo4j_client as db
from routes.query   import router as query_router
from routes.confirm import router as confirm_router
from routes.demo import router as demo_router
from routes.juspay import router as juspay_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    db.close()


app = FastAPI(
    title="Cerberus Threat Intelligence API",
    description=(
        "Cross-domain threat intelligence: Neo4j graph traversal + "
        "Anthropic LLM narrative generation with self-improving cache."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(query_router)
app.include_router(confirm_router)
app.include_router(demo_router)
app.include_router(juspay_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/rocketride/health")
async def rocketride_health():
    """
    Proxy health check for the RocketRide pipeline service.
    Frontend polls this to show a second status indicator alongside the
    backend dot — judges see two green dots confirming both integrations live.
    """
    import rocketride
    available = await rocketride.is_available()
    return {"status": "ok" if available else "unavailable", "available": available}


@app.get("/api/schema")
async def schema():
    """Return node labels and relationship types from the live graph."""
    import asyncio

    return await asyncio.to_thread(db.get_schema)
