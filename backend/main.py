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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/schema")
async def schema():
    """Return node labels and relationship types from the live graph."""
    import asyncio
    import neo4j_client as db

    def _query():
        with db._driver.session() as s:
            labels = [r["label"] for r in s.run("CALL db.labels() YIELD label")]
            rel_types = [r["relationshipType"] for r in
                         s.run("CALL db.relationshipTypes() YIELD relationshipType")]
            counts = s.run(
                "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count"
            ).data()
        return {"labels": labels, "relationship_types": rel_types, "counts": counts}

    return await asyncio.to_thread(_query)
