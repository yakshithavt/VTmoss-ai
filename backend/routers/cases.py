import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, UploadFile, File

from database import get_conn
from schemas import CaseCreate
from evidence.parser import parse_upload
from evidence.hashing import hash_report
from evidence.merkle import build_merkle_tree
from agents.investigator import investigate, compute_threat_score
from agents.counter_evidence import challenge
from agents.reviewer import review
from agents.trust_engine import compute_trust_score
from agents.response_agent import generate_response_plan
from blockchain.contract_client import register_case as chain_register, get_case as chain_get, BlockchainUnavailable

router = APIRouter(prefix="/api/cases", tags=["cases"])


def _row_to_evidence(row) -> dict:
    return {
        "evidence_id": row["evidence_id"],
        "case_id": row["case_id"],
        "source": row["source"],
        "evidence_type": row["evidence_type"],
        "timestamp": row["timestamp"],
        "content": json.loads(row["content"]),
        "content_hash": row["content_hash"],
        "metadata": json.loads(row["metadata"]),
        "severity": row["severity"],
        "confidence": row["confidence"],
    }


def _get_case_or_404(conn, case_id: str):
    row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, f"Case {case_id} not found")
    return row


@router.post("")
def create_case(payload: CaseCreate):
    with get_conn() as conn:
        existing = conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (payload.case_id,)).fetchone()
        if existing:
            raise HTTPException(409, f"Case {payload.case_id} already exists")
        conn.execute(
            "INSERT INTO cases (case_id, title, evidence_source, investigation_type, status) VALUES (?, ?, ?, ?, 'CREATED')",
            (payload.case_id, payload.title, payload.evidence_source, payload.investigation_type),
        )
    return {"case_id": payload.case_id, "status": "CREATED"}


@router.post("/{case_id}/evidence")
async def upload_evidence(case_id: str, file: UploadFile = File(...)):
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        raw = await file.read()
        try:
            items = parse_upload(file.filename, raw, case_id)
        except ValueError as e:
            raise HTTPException(400, str(e))

        for item in items:
            conn.execute(
                """INSERT OR REPLACE INTO evidence
                   (evidence_id, case_id, source, evidence_type, timestamp, content, content_hash, metadata, severity, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    item["evidence_id"], item["case_id"], item["source"], item["evidence_type"],
                    item["timestamp"], json.dumps(item["content"]), item["content_hash"],
                    json.dumps(item["metadata"]), item["severity"], item["confidence"],
                ),
            )
    return {"ingested": len(items), "evidence_ids": [i["evidence_id"] for i in items]}


@router.post("/{case_id}/investigate")
def run_investigation(case_id: str):
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        if not rows:
            raise HTTPException(400, "No evidence uploaded for this case yet")
        evidence_items = [_row_to_evidence(r) for r in rows]

        result = investigate(case_id, evidence_items)

        conn.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
        for f in result["findings"]:
            finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"
            conn.execute(
                """INSERT INTO findings (finding_id, case_id, title, mitre_id, confidence, supporting_evidence, status)
                   VALUES (?, ?, ?, ?, ?, ?, 'OPEN')""",
                (finding_id, case_id, f["title"], f["mitre_id"], f["confidence"], json.dumps(f["supporting_evidence"])),
            )

        conn.execute(
            "UPDATE cases SET status = 'INVESTIGATED', threat_score = ? WHERE case_id = ?",
            (result["threat_score"], case_id),
        )
    return result


@router.get("/{case_id}/findings")
def get_findings(case_id: str):
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        rows = conn.execute("SELECT * FROM findings WHERE case_id = ?", (case_id,)).fetchall()
        return [
            {
                "finding_id": r["finding_id"], "title": r["title"], "mitre_id": r["mitre_id"],
                "confidence": r["confidence"],
                "adjusted_confidence": r["adjusted_confidence"],
                "supporting_evidence": json.loads(r["supporting_evidence"] or "[]"),
                "contradicting_evidence": json.loads(r["contradicting_evidence"] or "[]"),
            }
            for r in rows
        ]


@router.get("/{case_id}/graph")
def get_graph(case_id: str):
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        evidence_items = [_row_to_evidence(r) for r in ev_rows]

    nodes, edges = [], []
    seen = set()

    def add_node(node_id, node_type, label):
        if node_id not in seen:
            nodes.append({"id": node_id, "type": node_type, "label": label})
            seen.add(node_id)

    for e in evidence_items:
        c = e["content"]
        chain = []
        if c.get("user"):
            add_node(f"user:{c['user']}", "user", c["user"]); chain.append(f"user:{c['user']}")
        if c.get("host"):
            add_node(f"host:{c['host']}", "host", c["host"]); chain.append(f"host:{c['host']}")
        if c.get("process"):
            add_node(f"process:{c['process']}", "process", c["process"]); chain.append(f"process:{c['process']}")
        if c.get("url") or c.get("domain"):
            label = c.get("url") or c.get("domain")
            add_node(f"url:{label}", "url", label); chain.append(f"url:{label}")
        if c.get("file"):
            add_node(f"file:{c['file']}", "file", c["file"]); chain.append(f"file:{c['file']}")

        node_id = f"evidence:{e['evidence_id']}"
        add_node(node_id, "evidence", e["evidence_id"])
        chain.append(node_id)

        for i in range(len(chain) - 1):
            edges.append({"source": chain[i], "target": chain[i + 1]})

    return {"nodes": nodes, "edges": edges}


@router.post("/{case_id}/challenge")
def run_counter_evidence(case_id: str):
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        finding_rows = conn.execute("SELECT * FROM findings WHERE case_id = ?", (case_id,)).fetchall()
        ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        evidence_by_id = {r["evidence_id"]: _row_to_evidence(r) for r in ev_rows}

        findings = [
            {
                "finding_id": r["finding_id"], "title": r["title"], "mitre_id": r["mitre_id"],
                "confidence": r["confidence"], "supporting_evidence": json.loads(r["supporting_evidence"] or "[]"),
            }
            for r in finding_rows
        ]

        challenged = challenge(findings, evidence_by_id)

        for c in challenged:
            conn.execute(
                """UPDATE findings SET adjusted_confidence = ?, contradicting_evidence = ? WHERE finding_id = ?""",
                (c["adjusted_confidence"], json.dumps(c["contradicting_evidence"]), c["finding_id"]),
            )
    return {"challenged_findings": challenged}


@router.post("/{case_id}/finalize")
def finalize_case(case_id: str):
    with get_conn() as conn:
        case_row = _get_case_or_404(conn, case_id)
        ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        finding_rows = conn.execute("SELECT * FROM findings WHERE case_id = ?", (case_id,)).fetchall()
        evidence_items = [_row_to_evidence(r) for r in ev_rows]
        evidence_by_id = {e["evidence_id"]: e for e in evidence_items}

        findings = [
            {
                "finding_id": r["finding_id"], "title": r["title"], "mitre_id": r["mitre_id"],
                "confidence": r["confidence"],
                "adjusted_confidence": r["adjusted_confidence"] if r["adjusted_confidence"] is not None else r["confidence"],
                "supporting_evidence": json.loads(r["supporting_evidence"] or "[]"),
                "contradicting_evidence": json.loads(r["contradicting_evidence"] or "[]"),
            }
            for r in finding_rows
        ]

        review_result = review(findings, evidence_by_id)
        trust = compute_trust_score(findings, evidence_items, review_result)

        # Recompute the threat score from POST-CHALLENGE confidences, so a
        # finding the Counter-Evidence Agent successfully explained away
        # actually pulls the case's threat level down, not just a footnote.
        threat_score = compute_threat_score(findings, confidence_key="adjusted_confidence")

        verdict = "Likely benign"
        if threat_score >= 85 and trust["evidence_trust_score"] >= 70:
            verdict = "Likely compromised"
        elif threat_score >= 40:
            verdict = "Suspicious"

        report = {
            "case_id": case_id,
            "title": case_row["title"],
            "threat_score": threat_score,
            "evidence_trust_score": trust["evidence_trust_score"],
            "verdict": verdict,
            "findings": findings,
            "review": review_result,
            "finalized_at": datetime.now(timezone.utc).isoformat(),
        }

        conn.execute(
            "UPDATE cases SET status = 'FINALIZED', evidence_trust_score = ?, final_verdict = ? WHERE case_id = ?",
            (trust["evidence_trust_score"], verdict, case_id),
        )
    return {"report": report, "trust": trust, "review": review_result}


@router.post("/{case_id}/anchor")
def anchor_case(case_id: str):
    with get_conn() as conn:
        case_row = _get_case_or_404(conn, case_id)
        if case_row["status"] != "FINALIZED":
            raise HTTPException(400, "Case must be finalized before it can be anchored")
        ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        evidence_hashes = [r["content_hash"] for r in ev_rows]
        if not evidence_hashes:
            raise HTTPException(400, "No evidence to anchor")

        merkle = build_merkle_tree(evidence_hashes)
        report_for_hash = {
            "case_id": case_id,
            "threat_score": case_row["threat_score"],
            "evidence_trust_score": case_row["evidence_trust_score"],
            "verdict": case_row["final_verdict"],
        }
        report_hash = hash_report(report_for_hash)

        try:
            chain_result = chain_register(case_id, merkle["root"], report_hash)
            mode = "on-chain"
        except BlockchainUnavailable:
            chain_result = {"transaction_hash": None, "contract_address": None, "network": "SIMULATED (blockchain unreachable)", "status": "simulated"}
            mode = "simulated"
        except Exception as e:
            if "CaseAlreadyRegistered" in str(e):
                raise HTTPException(409, f"Case {case_id} is already anchored on-chain (registrations are immutable by design). "
                                          f"Anchor a revised report under a new case_id, e.g. '{case_id}-v2'.")
            raise HTTPException(502, f"On-chain registration failed: {e}")

        conn.execute(
            """INSERT OR REPLACE INTO blockchain_records
               (case_id, merkle_root, report_hash, transaction_hash, contract_address, network, mode, registered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (case_id, merkle["root"], report_hash, chain_result.get("transaction_hash"),
             chain_result.get("contract_address"), chain_result.get("network"), mode,
             datetime.now(timezone.utc).isoformat()),
        )
        conn.execute("UPDATE cases SET status = 'ANCHORED' WHERE case_id = ?", (case_id,))

    return {"case_id": case_id, "merkle_root": merkle["root"], "report_hash": report_hash, **chain_result, "mode": mode}


@router.get("/{case_id}/verify")
def verify_case(case_id: str):
    with get_conn() as conn:
        case_row = _get_case_or_404(conn, case_id)
        bc_row = conn.execute("SELECT * FROM blockchain_records WHERE case_id = ?", (case_id,)).fetchone()
        if not bc_row:
            raise HTTPException(400, "Case has not been anchored yet")

        ev_rows = conn.execute("SELECT * FROM evidence WHERE case_id = ?", (case_id,)).fetchall()
        current_evidence_hashes = [r["content_hash"] for r in ev_rows]
        current_merkle_root = build_merkle_tree(current_evidence_hashes)["root"]

        current_report = {
            "case_id": case_id,
            "threat_score": case_row["threat_score"],
            "evidence_trust_score": case_row["evidence_trust_score"],
            "verdict": case_row["final_verdict"],
        }
        current_report_hash = hash_report(current_report)

        if bc_row["mode"] == "on-chain":
            try:
                onchain = chain_get(case_id)
                registered_root = onchain["merkle_root"]
                registered_report_hash = onchain["report_hash"]
            except BlockchainUnavailable:
                registered_root = bc_row["merkle_root"]
                registered_report_hash = bc_row["report_hash"]
        else:
            registered_root = bc_row["merkle_root"]
            registered_report_hash = bc_row["report_hash"]

        root_match = current_merkle_root == registered_root
        report_match = current_report_hash == registered_report_hash
        verified = root_match and report_match

    return {
        "verified": verified,
        "status": "VERIFIED" if verified else "INTEGRITY_FAILURE",
        "registered_merkle_root": registered_root,
        "current_merkle_root": current_merkle_root,
        "registered_report_hash": registered_report_hash,
        "current_report_hash": current_report_hash,
        "mismatch": {
            "merkle_root": not root_match,
            "report_hash": not report_match,
        },
    }


@router.post("/{case_id}/tamper")
def tamper_case(case_id: str, new_threat_score: int):
    """Demo-only endpoint: intentionally mutate a finalized report's threat
    score AFTER anchoring, so /verify can be shown failing (per the mandatory
    tamper demonstration in the spec), then restored."""
    with get_conn() as conn:
        _get_case_or_404(conn, case_id)
        conn.execute("UPDATE cases SET threat_score = ? WHERE case_id = ?", (new_threat_score, case_id))
    return {"case_id": case_id, "threat_score": new_threat_score, "note": "Report mutated post-anchor for tamper demonstration"}


@router.get("/{case_id}/response-plan")
def response_plan(case_id: str):
    with get_conn() as conn:
        case_row = _get_case_or_404(conn, case_id)
    severity = "CRITICAL" if (case_row["threat_score"] or 0) >= 90 else "HIGH" if (case_row["threat_score"] or 0) >= 70 else "MEDIUM" if (case_row["threat_score"] or 0) >= 40 else "LOW"
    return {"severity": severity, "actions": generate_response_plan(severity)}


@router.get("/{case_id}")
def get_case_detail(case_id: str):
    with get_conn() as conn:
        row = _get_case_or_404(conn, case_id)
        return dict(row)


@router.get("")
def list_cases():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
