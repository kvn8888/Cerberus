"""
routes/annotations.py — Annotation CRUD for graph entities.

Analysts can attach timestamped notes to any entity in the graph.
Annotations are stored as Neo4j relationship properties on a
(:Annotation)-[:ANNOTATES]->(:Entity) pattern, making them
queryable alongside the investigation graph.

Endpoints:
  GET    /api/annotations?entity=X          — list annotations for entity
  POST   /api/annotations                   — create annotation
  DELETE /api/annotations/{annotation_id}   — delete annotation
"""

from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import neo4j_client as db

router = APIRouter(prefix="/api/annotations")


class CreateAnnotation(BaseModel):
    """Payload for creating a new annotation on an entity."""
    entity: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1, max_length=2000)
    author: str = Field(default="analyst")


class AnnotationOut(BaseModel):
    """Shape returned by list/create endpoints."""
    id: str
    entity: str
    text: str
    author: str
    created_at: int


@router.get("")
async def list_annotations(entity: str):
    """Return all annotations attached to a given entity node."""
    entity = entity.strip()
    if not entity:
        raise HTTPException(status_code=400, detail="entity is required")

    # Cypher: find all Annotation nodes linked to the target entity
    query = """
    MATCH (a:Annotation)-[:ANNOTATES]->(e)
    WHERE e.name = $entity OR e.id = $entity
    RETURN a.id AS id, a.entity AS entity, a.text AS text,
           a.author AS author, a.created_at AS created_at
    ORDER BY a.created_at DESC
    """
    records = db.run_query(query, {"entity": entity})
    return [
        AnnotationOut(
            id=r["id"],
            entity=r["entity"],
            text=r["text"],
            author=r["author"] or "analyst",
            created_at=r["created_at"] or 0,
        )
        for r in records
    ]


@router.post("", status_code=201)
async def create_annotation(req: CreateAnnotation):
    """Create a new annotation node and link it to the target entity."""
    annotation_id = f"ann-{uuid.uuid4().hex[:12]}"
    created_at = int(time.time() * 1000)

    # MERGE the annotation node, then link it to any node matching the entity
    query = """
    MATCH (e)
    WHERE e.name = $entity OR e.id = $entity
    WITH e LIMIT 1
    CREATE (a:Annotation {
        id: $id,
        entity: $entity,
        text: $text,
        author: $author,
        created_at: $created_at
    })
    CREATE (a)-[:ANNOTATES]->(e)
    RETURN a.id AS id
    """
    records = db.run_query(query, {
        "id": annotation_id,
        "entity": req.entity.strip(),
        "text": req.text.strip(),
        "author": req.author.strip(),
        "created_at": created_at,
    })

    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"Entity '{req.entity}' not found in graph"
        )

    return AnnotationOut(
        id=annotation_id,
        entity=req.entity.strip(),
        text=req.text.strip(),
        author=req.author.strip(),
        created_at=created_at,
    )


@router.delete("/{annotation_id}")
async def delete_annotation(annotation_id: str):
    """Delete an annotation by its unique ID."""
    query = """
    MATCH (a:Annotation {id: $id})
    DETACH DELETE a
    RETURN count(a) AS deleted
    """
    records = db.run_query(query, {"id": annotation_id})
    deleted = records[0]["deleted"] if records else 0
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Annotation not found")
    return {"deleted": True}
