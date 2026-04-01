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
from routes.ingest import router as ingest_router
from routes.threatmap import router as threatmap_router
from routes.juspay import router as juspay_router
from routes.intelligence import router as intelligence_router
from routes.auth_routes import router as auth_router
from routes.apikeys import router as apikeys_router
from routes.stix import router as stix_router
from routes.diff import router as diff_router
from routes.enrichment import router as enrichment_router
from routes.annotations import router as annotations_router
from routes.watchlist import router as watchlist_router


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
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.middleware("http")
async def cors_on_error(request, call_next):
    """Ensure CORS headers are present even on 500 errors."""
    try:
        response = await call_next(request)
    except Exception:
        from fastapi.responses import JSONResponse
        response = JSONResponse({"detail": "Internal server error"}, status_code=500)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response

app.include_router(query_router)
app.include_router(confirm_router)
app.include_router(demo_router)
app.include_router(ingest_router)
app.include_router(threatmap_router)
app.include_router(juspay_router)
app.include_router(intelligence_router)
app.include_router(stix_router)
app.include_router(diff_router)
app.include_router(auth_router)
app.include_router(apikeys_router)
app.include_router(enrichment_router)
app.include_router(annotations_router)
app.include_router(watchlist_router)


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
    import pipeline
    available = await pipeline.is_available()
    return {"status": "ok" if available else "unavailable", "available": available}


@app.get("/api/schema")
async def schema():
    """Return node labels and relationship types from the live graph."""
    import asyncio

    return await asyncio.to_thread(db.get_schema)


@app.get("/api/memory")
async def memory():
    """Return all memorized (confirmed) entities and their connections."""
    import asyncio

    return await asyncio.to_thread(db.get_memory)


@app.get("/api/memory/geo")
async def memory_geo():
    """Return geo-plottable points from all memorized (confirmed) entities."""
    import asyncio

    points = await asyncio.to_thread(db.get_memory_geo)
    return {"points": points}


@app.get("/api/geomap/all")
async def geomap_all():
    """
    Return geo-plottable points for ALL IPs and ThreatActors in the graph,
    regardless of confirmation status. Used to pre-populate the geomap on
    first load so real Neo4j data shows immediately without any investigation.
    """
    import asyncio

    points = await asyncio.to_thread(db.get_all_geo)
    return {"points": points}


@app.get("/api/memory/expand")
async def memory_expand(node: str):
    """Return the children of a specific memorized node (click-to-expand)."""
    import asyncio

    return await asyncio.to_thread(db.get_memory_expand, node)
