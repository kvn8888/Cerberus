"""
routes/diff.py — Graph diffing / comparison endpoint.

Compares the investigation graphs of two entities and returns the structural
overlap: shared nodes, exclusive nodes, shared links, exclusive links, and a
0–1 overlap score.  Useful for identifying infrastructure shared between
threat actors or supply-chain overlap between packages.

Endpoint:
  POST /api/diff/compare  — compare two entity graphs
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import neo4j_client as db
from models import EntityType

router = APIRouter(prefix="/api/diff")


class DiffRequest(BaseModel):
    entity_a: str
    type_a: EntityType
    entity_b: str
    type_b: EntityType


def _node_set(nodes: list[dict[str, Any]]) -> set[str]:
    """Extract the set of node IDs from a get_graph() node list."""
    return {n["id"] for n in nodes if "id" in n}


def _link_key(link: dict[str, Any]) -> tuple[str, str]:
    """Canonical key for a link — sorted pair so direction doesn't matter."""
    src = link.get("source", "")
    tgt = link.get("target", "")
    return (min(src, tgt), max(src, tgt))


def _link_set(links: list[dict[str, Any]]) -> set[tuple[str, str]]:
    """Extract a set of canonical (source, target) pairs from links."""
    return {_link_key(lnk) for lnk in links}


def _filter_nodes(nodes: list[dict[str, Any]], ids: set[str]) -> list[dict[str, Any]]:
    """Return only nodes whose id is in *ids*."""
    return [n for n in nodes if n.get("id") in ids]


def _filter_links(
    links: list[dict[str, Any]], keys: set[tuple[str, str]]
) -> list[dict[str, Any]]:
    """Return only links whose canonical key is in *keys*."""
    return [lnk for lnk in links if _link_key(lnk) in keys]


@router.post("/compare")
async def compare(req: DiffRequest):
    """
    Compare the investigation graphs of two entities.

    1. Fetch both graphs in parallel via db.get_graph()
    2. Compute set-level overlap on node IDs and link (source,target) pairs
    3. Return shared / exclusive partitions plus a 0–1 overlap score
    """
    graph_a, graph_b = await asyncio.gather(
        asyncio.to_thread(db.get_graph, req.entity_a, req.type_a.value),
        asyncio.to_thread(db.get_graph, req.entity_b, req.type_b.value),
    )

    nodes_a = graph_a.get("nodes", [])
    nodes_b = graph_b.get("nodes", [])
    links_a = graph_a.get("links", [])
    links_b = graph_b.get("links", [])

    ids_a = _node_set(nodes_a)
    ids_b = _node_set(nodes_b)

    shared_ids = ids_a & ids_b
    only_a_ids = ids_a - ids_b
    only_b_ids = ids_b - ids_a
    all_ids = ids_a | ids_b

    lkeys_a = _link_set(links_a)
    lkeys_b = _link_set(links_b)

    shared_lkeys = lkeys_a & lkeys_b
    only_a_lkeys = lkeys_a - lkeys_b
    only_b_lkeys = lkeys_b - lkeys_a

    overlap_score = len(shared_ids) / len(all_ids) if all_ids else 0.0

    # Merge both node lists so shared nodes carry data from graph A (arbitrary)
    all_nodes = {n["id"]: n for n in nodes_b}
    all_nodes.update({n["id"]: n for n in nodes_a})

    all_links = links_a + links_b

    return {
        "shared_nodes": _filter_nodes(list(all_nodes.values()), shared_ids),
        "only_a": _filter_nodes(list(all_nodes.values()), only_a_ids),
        "only_b": _filter_nodes(list(all_nodes.values()), only_b_ids),
        "shared_links": _filter_links(all_links, shared_lkeys),
        "only_a_links": _filter_links(all_links, only_a_lkeys),
        "only_b_links": _filter_links(all_links, only_b_lkeys),
        "overlap_score": round(overlap_score, 4),
        "summary": {
            "total_unique_nodes": len(all_ids),
            "shared_count": len(shared_ids),
            "only_a_count": len(only_a_ids),
            "only_b_count": len(only_b_ids),
            "total_unique_links": len(lkeys_a | lkeys_b),
            "shared_links_count": len(shared_lkeys),
            "only_a_links_count": len(only_a_lkeys),
            "only_b_links_count": len(only_b_lkeys),
        },
    }
