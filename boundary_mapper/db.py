"""SQLite-backed fact storage for boundary mapping.

Stores symbols, edges, surfaces, flows, and findings with full evidence.
Designed for incremental reruns — facts are upserted, not duplicated.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from .models import (
    BoundaryFlow, BoundarySurface, Confidence, EdgeKind, Evidence,
    ExtractionMethod, Finding, FindingSeverity, FlowStep, GraphEdge,
    Side, SymbolKind, SymbolNode, WiringStatus, BoundaryType,
)

SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS symbols (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    qualified_name TEXT DEFAULT '',
    kind TEXT NOT NULL,
    side TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER DEFAULT 0,
    line_end INTEGER DEFAULT 0,
    properties TEXT DEFAULT '{}',
    UNIQUE(name, kind, file_path, line_start)
);

CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    confidence TEXT DEFAULT 'medium',
    properties TEXT DEFAULT '{}',
    FOREIGN KEY (source_id) REFERENCES symbols(id),
    FOREIGN KEY (target_id) REFERENCES symbols(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_type TEXT NOT NULL,   -- 'symbol', 'edge', 'surface', 'flow', 'finding'
    parent_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER DEFAULT 0,
    line_end INTEGER DEFAULT 0,
    symbol TEXT DEFAULT '',
    snippet TEXT DEFAULT '',
    method TEXT DEFAULT 'pattern_match',
    confidence TEXT DEFAULT 'medium',
    note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS surfaces (
    id TEXT PRIMARY KEY,
    boundary_type TEXT NOT NULL,
    name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    kernel_entrypoint TEXT DEFAULT '',
    userspace_producer TEXT DEFAULT '',
    shared_contract TEXT DEFAULT '',
    dispatch_key TEXT DEFAULT '',
    handler TEXT DEFAULT '',
    response_path TEXT DEFAULT '',
    status TEXT DEFAULT 'declared',
    properties TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    name TEXT DEFAULT '',
    boundary_type TEXT DEFAULT 'custom',
    status TEXT DEFAULT 'declared'
);

CREATE TABLE IF NOT EXISTS flow_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL,
    step_order INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    symbol_id TEXT DEFAULT '',
    side TEXT DEFAULT 'unknown',
    action TEXT DEFAULT '',
    FOREIGN KEY (flow_id) REFERENCES flows(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'medium',
    category TEXT DEFAULT '',
    status TEXT DEFAULT 'declared',
    recommendation TEXT DEFAULT '',
    related_symbols TEXT DEFAULT '[]',
    related_flows TEXT DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
CREATE INDEX IF NOT EXISTS idx_symbols_side ON symbols(side);
CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file_path);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);
CREATE INDEX IF NOT EXISTS idx_evidence_parent ON evidence(parent_type, parent_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
"""


def _gen_id() -> str:
    return uuid.uuid4().hex[:12]


class FactStore:
    """SQLite fact store with upsert semantics."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self):
        self.conn.executescript(SCHEMA_SQL)
        self._migrate()
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )
        self.conn.commit()

    def _migrate(self):
        """Apply schema migrations for existing databases."""
        try:
            row = self.conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            old_ver = int(row["value"]) if row else 1
        except Exception:
            old_ver = 1
        if old_ver < 2:
            # v2: add properties column to surfaces
            try:
                self.conn.execute(
                    "ALTER TABLE surfaces ADD COLUMN properties TEXT DEFAULT '{}'"
                )
            except Exception:
                pass  # column already exists

    def close(self):
        self.conn.close()

    # -- Symbols --

    def upsert_symbol(self, sym: SymbolNode) -> str:
        if not sym.id:
            sym.id = _gen_id()
        self.conn.execute(
            """INSERT INTO symbols(id, name, qualified_name, kind, side,
                                    file_path, line_start, line_end, properties)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name, kind, file_path, line_start)
               DO UPDATE SET qualified_name=excluded.qualified_name,
                             side=excluded.side,
                             line_end=excluded.line_end,
                             properties=excluded.properties""",
            (sym.id, sym.name, sym.qualified_name, sym.kind.value, sym.side.value,
             sym.file_path, sym.line_start, sym.line_end,
             json.dumps(sym.properties)),
        )
        for ev in sym.evidence:
            self._insert_evidence("symbol", sym.id, ev)
        self.conn.commit()
        return sym.id

    def get_symbol(self, symbol_id: str) -> Optional[SymbolNode]:
        row = self.conn.execute(
            "SELECT * FROM symbols WHERE id = ?", (symbol_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_symbol(row)

    def find_symbols(self, name: str = "", kind: str = "",
                     side: str = "", file_path: str = "",
                     limit: int = 100) -> list[SymbolNode]:
        clauses, params = [], []
        if name:
            clauses.append("name LIKE ?")
            params.append(f"%{name}%")
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if side:
            clauses.append("side = ?")
            params.append(side)
        if file_path:
            clauses.append("file_path LIKE ?")
            params.append(f"%{file_path}%")
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM symbols WHERE {where} LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [self._row_to_symbol(r) for r in rows]

    def _row_to_symbol(self, row) -> SymbolNode:
        return SymbolNode(
            id=row["id"],
            name=row["name"],
            qualified_name=row["qualified_name"],
            kind=SymbolKind(row["kind"]),
            side=Side(row["side"]),
            file_path=row["file_path"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            evidence=self._get_evidence("symbol", row["id"]),
            properties=json.loads(row["properties"]),
        )

    # -- Edges --

    def add_edge(self, edge: GraphEdge) -> str:
        if not edge.id:
            edge.id = _gen_id()
        try:
            self.conn.execute(
                """INSERT OR REPLACE INTO edges(id, source_id, target_id, kind,
                                                 confidence, properties)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (edge.id, edge.source_id, edge.target_id, edge.kind.value,
                 edge.confidence.value, json.dumps(edge.properties)),
            )
            for ev in edge.evidence:
                self._insert_evidence("edge", edge.id, ev)
            self.conn.commit()
        except sqlite3.IntegrityError:
            # FK constraint — source or target symbol missing, skip edge
            self.conn.rollback()
            return ""
        return edge.id

    def get_edges(self, source_id: str = "", target_id: str = "",
                  kind: str = "", limit: int = 500) -> list[GraphEdge]:
        clauses, params = [], []
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM edges WHERE {where} LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def _row_to_edge(self, row) -> GraphEdge:
        return GraphEdge(
            id=row["id"],
            source_id=row["source_id"],
            target_id=row["target_id"],
            kind=EdgeKind(row["kind"]),
            confidence=Confidence(row["confidence"]),
            evidence=self._get_evidence("edge", row["id"]),
            properties=json.loads(row["properties"]),
        )

    # -- Surfaces --

    def upsert_surface(self, surf: BoundarySurface) -> str:
        if not surf.id:
            surf.id = _gen_id()
        self.conn.execute(
            """INSERT OR REPLACE INTO surfaces(id, boundary_type, name,
               description, kernel_entrypoint, userspace_producer,
               shared_contract, dispatch_key, handler, response_path, status,
               properties)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (surf.id, surf.boundary_type.value, surf.name, surf.description,
             surf.kernel_entrypoint, surf.userspace_producer,
             surf.shared_contract, surf.dispatch_key, surf.handler,
             surf.response_path, surf.status.value,
             json.dumps(surf.properties)),
        )
        for ev in surf.evidence:
            self._insert_evidence("surface", surf.id, ev)
        self.conn.commit()
        return surf.id

    def get_surfaces(self, boundary_type: str = "",
                     status: str = "") -> list[BoundarySurface]:
        clauses, params = [], []
        if boundary_type:
            clauses.append("boundary_type = ?")
            params.append(boundary_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM surfaces WHERE {where}", params
        ).fetchall()
        return [self._row_to_surface(r) for r in rows]

    def _row_to_surface(self, row) -> BoundarySurface:
        props_raw = row["properties"] if "properties" in row.keys() else "{}"
        return BoundarySurface(
            id=row["id"],
            boundary_type=BoundaryType(row["boundary_type"]),
            name=row["name"],
            description=row["description"],
            kernel_entrypoint=row["kernel_entrypoint"],
            userspace_producer=row["userspace_producer"],
            shared_contract=row["shared_contract"],
            dispatch_key=row["dispatch_key"],
            handler=row["handler"],
            response_path=row["response_path"],
            status=WiringStatus(row["status"]),
            evidence=self._get_evidence("surface", row["id"]),
            properties=json.loads(props_raw or "{}"),
        )

    # -- Flows --

    def upsert_flow(self, flow: BoundaryFlow) -> str:
        if not flow.id:
            flow.id = _gen_id()
        self.conn.execute(
            """INSERT OR REPLACE INTO flows(id, name, boundary_type, status)
               VALUES (?, ?, ?, ?)""",
            (flow.id, flow.name, flow.boundary_type.value, flow.status.value),
        )
        # Replace steps
        self.conn.execute("DELETE FROM flow_steps WHERE flow_id = ?", (flow.id,))
        for step in flow.steps:
            self.conn.execute(
                """INSERT INTO flow_steps(flow_id, step_order, description,
                   symbol_id, side, action)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (flow.id, step.order, step.description, step.symbol_id,
                 step.side.value, step.action),
            )
            for ev in step.evidence:
                self._insert_evidence("flow_step", f"{flow.id}:{step.order}", ev)
        for ev in flow.evidence:
            self._insert_evidence("flow", flow.id, ev)
        self.conn.commit()
        return flow.id

    # -- Findings --

    def upsert_finding(self, finding: Finding) -> str:
        if not finding.id:
            finding.id = _gen_id()
        self.conn.execute(
            """INSERT OR REPLACE INTO findings(id, title, description, severity,
               category, status, recommendation, related_symbols, related_flows)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding.id, finding.title, finding.description,
             finding.severity.value, finding.category, finding.status.value,
             finding.recommendation,
             json.dumps(finding.related_symbols),
             json.dumps(finding.related_flows)),
        )
        for ev in finding.evidence:
            self._insert_evidence("finding", finding.id, ev)
        self.conn.commit()
        return finding.id

    def get_findings(self, severity: str = "", category: str = "",
                     limit: int = 200) -> list[Finding]:
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if category:
            clauses.append("category = ?")
            params.append(category)
        where = " AND ".join(clauses) if clauses else "1=1"
        rows = self.conn.execute(
            f"SELECT * FROM findings WHERE {where} LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def _row_to_finding(self, row) -> Finding:
        return Finding(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            severity=FindingSeverity(row["severity"]),
            category=row["category"],
            status=WiringStatus(row["status"]),
            evidence=self._get_evidence("finding", row["id"]),
            related_symbols=json.loads(row["related_symbols"]),
            related_flows=json.loads(row["related_flows"]),
            recommendation=row["recommendation"],
        )

    # -- Evidence --

    def _insert_evidence(self, parent_type: str, parent_id: str, ev: Evidence):
        self.conn.execute(
            """INSERT INTO evidence(parent_type, parent_id, file_path,
               line_start, line_end, symbol, snippet, method, confidence, note)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (parent_type, parent_id, ev.file_path, ev.line_start, ev.line_end,
             ev.symbol, ev.snippet, ev.method.value, ev.confidence.value, ev.note),
        )

    def _get_evidence(self, parent_type: str, parent_id: str) -> list[Evidence]:
        rows = self.conn.execute(
            """SELECT * FROM evidence WHERE parent_type = ? AND parent_id = ?""",
            (parent_type, parent_id),
        ).fetchall()
        return [
            Evidence(
                file_path=r["file_path"],
                line_start=r["line_start"],
                line_end=r["line_end"],
                symbol=r["symbol"],
                snippet=r["snippet"],
                method=ExtractionMethod(r["method"]),
                confidence=Confidence(r["confidence"]),
                note=r["note"],
            )
            for r in rows
        ]

    # -- Stats --

    def stats(self) -> dict:
        result = {}
        for table in ("symbols", "edges", "surfaces", "flows", "findings", "evidence"):
            row = self.conn.execute(f"SELECT COUNT(*) as c FROM {table}").fetchone()
            result[table] = row["c"]
        return result

    # -- Cleanup --

    def clear_all(self):
        for table in ("evidence", "flow_steps", "flows", "findings",
                       "surfaces", "edges", "symbols"):
            self.conn.execute(f"DELETE FROM {table}")
        self.conn.commit()
