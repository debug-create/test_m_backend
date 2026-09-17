"""Deterministic NetworkX evidence graph and response blast-radius analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import networkx as nx
from sqlalchemy.orm import Session

from models.db_models import Case, ContextLedgerEntry, Entity, Event, ResponseAction


def _node_id(kind: str, value: Any) -> str:
    return f"{kind}:{value}"


def build_evidence_graph(db: Session, case: Case, *, now: datetime | None = None) -> dict[str, Any]:
    actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
    events = db.query(Event).filter(Event.id.in_(case.event_ids or [-1])).order_by(
        Event.timestamp, Event.id
    ).all()
    explanations = {row["event_id"]: row for row in (case.explanation_breakdown or [])}
    graph = nx.DiGraph()
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(node_id: str, kind: str, label: str, **meta: Any) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": label, "meta": meta})
        graph.add_node(node_id, type=kind)

    def add_edge(source: str, target: str, edge_type: str, event_id: int | None = None) -> None:
        edge_id = f"{edge_type}:{source}:{target}:{event_id or 0}"
        edges.append({
            "id": edge_id, "source": source, "target": target,
            "type": edge_type, "event_id": event_id,
        })
        graph.add_edge(source, target, type=edge_type)

    entity_node = _node_id("entity", actor.pseudonymous_id)
    case_node = _node_id("case", case.id)
    add_node(entity_node, "entity", actor.pseudonymous_id)
    add_node(case_node, "case", f"Case {case.id}")
    add_edge(entity_node, case_node, "triggered")

    for event in events:
        device = _node_id("device", event.device_id)
        session = _node_id("session", event.device_id)
        add_node(device, "device", event.device_id)
        add_node(session, "session", event.device_id)
        add_edge(entity_node, session, "owns-session", event.id)
        add_edge(session, device, "authenticated-from", event.id)
        if event.resource_id:
            resource = _node_id("resource", event.resource_id)
            add_node(resource, "resource", event.resource_id,
                     classification=event.resource_classification)
            relation = "downloaded-from" if event.action == "file_download" else "accessed"
            add_edge(session, resource, relation, event.id)
        if event.destination:
            destination = _node_id("destination", event.destination)
            add_node(destination, "destination", event.destination)
            add_edge(session, destination, "uploaded-to", event.id)
        if event.action in {"privilege_change", "permission_request"}:
            privilege = _node_id("privilege", event.resource_id or "unspecified")
            add_node(privilege, "privilege", event.resource_id or "unspecified")
            add_edge(session, privilege, "requested-privilege", event.id)

    contexts = db.query(ContextLedgerEntry).filter(
        ContextLedgerEntry.id.in_(case.matched_context_ids or [-1])
    ).order_by(ContextLedgerEntry.id).all()
    for context in contexts:
        context_node = _node_id("context", context.id)
        add_node(context_node, "context revision", f"Context {context.id}",
                 late_context=bool(context.late_context))
        add_edge(context_node, case_node, "authorised-by")

    actions = db.query(ResponseAction).filter(
        ResponseAction.case_id == case.id
    ).order_by(ResponseAction.action_id).all()
    for action in actions:
        action_node = _node_id("response-action", action.action_id)
        add_node(action_node, "response action", action.action_type, status=action.status)
        add_edge(case_node, action_node, "controlled-by")
        for value in (action.target_scope or {}).values():
            candidates = [node_id for node_id in nodes if node_id.endswith(f":{value}")]
            for target in sorted(candidates):
                add_edge(action_node, target, "affected-by")

    # NetworkX operations are used for cycle detection and observed activity paths.
    cycles = sorted([cycle for cycle in nx.simple_cycles(graph)], key=lambda row: tuple(row))
    target_nodes = sorted(
        node_id for node_id, attrs in graph.nodes(data=True)
        if attrs.get("type") in {"resource", "destination", "privilege"}
    )
    paths: list[list[str]] = []
    for target in target_nodes:
        try:
            paths.append(nx.shortest_path(graph, entity_node, target))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    # Preserve explanation status as edge metadata without asserting causality.
    for edge in edges:
        detail = explanations.get(edge.get("event_id"))
        if detail:
            edge["explanation_status"] = detail.get("status")
    return {
        "case_id": case.id,
        "entity_ref": actor.pseudonymous_id,
        "generated_at": now or datetime.now(timezone.utc),
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: item["id"]),
        "evidence_paths": sorted(paths, key=lambda row: tuple(row)),
        "cycles": cycles,
    }


def preview_blast_radius(
    graph_data: dict[str, Any], target_scope: dict[str, Any], explanations: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes = graph_data["nodes"]
    values = set(target_scope.values())
    affected = [node for node in nodes if node["label"] in values]
    statuses = {row["event_id"]: row.get("status") for row in explanations}
    affected_event_ids = sorted({
        edge["event_id"] for edge in graph_data["edges"]
        if edge.get("event_id") is not None
        and (edge["source"] in {node["id"] for node in affected}
             or edge["target"] in {node["id"] for node in affected})
    })
    legitimate = [event_id for event_id in affected_event_ids
                  if statuses.get(event_id) in {"explained", "partially_explained"}]
    all_event_ids = sorted(statuses)
    return {
        "affected_sessions": sorted(node["label"] for node in affected if node["type"] == "session"),
        "affected_resources": sorted(node["label"] for node in affected if node["type"] == "resource"),
        "affected_destinations": sorted(node["label"] for node in affected if node["type"] == "destination"),
        "affected_permissions": sorted(node["label"] for node in affected if node["type"] == "privilege"),
        "potentially_disrupted_legitimate_activity": legitimate,
        "unaffected_activity": sorted(set(all_event_ids) - set(affected_event_ids)),
        "affected_event_ids": affected_event_ids,
        "evidence_paths": [
            path for path in graph_data["evidence_paths"]
            if any(path[-1] == node["id"] for node in affected)
        ],
        "graph_generated_at": (
            graph_data["generated_at"].isoformat()
            if hasattr(graph_data["generated_at"], "isoformat")
            else graph_data["generated_at"]
        ),
    }


def valid_scope_values(graph_data: dict[str, Any]) -> set[str]:
    return {
        node["label"] for node in graph_data["nodes"]
        if node["type"] in {"device", "session", "resource", "destination", "privilege", "entity"}
    }
