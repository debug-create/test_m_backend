"""
Verification: edit Arjun's context ledger and assert residual_risk decreases.

Run:
  python -m tests.test_context_edit

This is the exact interaction a judge may ask to see live.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running as script from project root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database import SessionLocal, init_db
from engine.case_builder import recompute_case
from models.db_models import Case, ContextLedgerEntry, Entity
from seed.scenarios import clear_all, run_seed


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        # Fresh seed for deterministic check
        clear_all(db)
        run_seed(db)

        arjun = db.query(Entity).filter(Entity.display_name == "Arjun").one()
        case = (
            db.query(Case)
            .filter(Case.actor_id == arjun.id)
            .order_by(Case.created_at.desc())
            .first()
        )
        assert case is not None, "Arjun case missing"

        case = recompute_case(db, case)
        before = case.residual_risk
        before_cov = case.context_coverage
        print(f"BEFORE edit: residual_risk={before:.4f} context_coverage={before_cov:.4f}")

        breakdown = case.explanation_breakdown or []
        statuses = {b["resource_id"]: b["status"] for b in breakdown if b.get("resource_id")}
        print(f"  per-resource status sample: {statuses}")

        # Assert partial explanation exists
        explained = [b for b in breakdown if b["status"] == "explained"]
        unexplained = [b for b in breakdown if b["status"] == "unexplained"]
        assert any(
            b.get("resource_id") == "migration-repo" and b["status"] == "explained"
            for b in breakdown
        ), "migration-repo should be explained"
        assert any(
            b.get("resource_id") == "finance-archive" and b["status"] == "unexplained"
            for b in breakdown
        ), "finance-archive should be unexplained"
        assert explained and unexplained, "Expected both explained and unexplained events"

        # Edit context: add finance-archive to allowed_resources
        entry = (
            db.query(ContextLedgerEntry)
            .filter(ContextLedgerEntry.actor_id == arjun.id)
            .first()
        )
        assert entry is not None
        resources = list(entry.allowed_resources or [])
        if "finance-archive" not in resources:
            resources.append("finance-archive")
        entry.allowed_resources = resources
        # Also allow the external destination to further increase coverage
        dests = list(entry.approved_destinations or [])
        if "https://personal-cloud.example/upload" not in dests:
            dests.append("https://personal-cloud.example/upload")
        entry.approved_destinations = dests
        # Allow external_upload action
        actions = list(entry.allowed_actions or [])
        if "external_upload" not in actions:
            actions.append("external_upload")
        entry.allowed_actions = actions
        db.commit()

        case = recompute_case(db, case)
        after = case.residual_risk
        after_cov = case.context_coverage
        print(f"AFTER edit:  residual_risk={after:.4f} context_coverage={after_cov:.4f}")

        breakdown2 = case.explanation_breakdown or []
        print("  updated breakdown:")
        for b in breakdown2:
            print(
                f"    {b['action']} {b.get('resource_id')} "
                f"{b.get('destination')}: {b['status']}"
            )

        assert after < before - 1.0, (
            f"residual_risk should visibly decrease after context edit "
            f"(before={before}, after={after})"
        )
        assert after_cov >= before_cov, "context_coverage should not decrease"
        print("PASS: residual_risk decreased after ContextLedgerEntry edit.")

        # Also sanity-check Priya low / Devraj high / Arjun mid
        priya = db.query(Entity).filter(Entity.display_name == "Priya").one()
        pcase = db.query(Case).filter(Case.actor_id == priya.id).one()
        pcase = recompute_case(db, pcase)

        comp = db.query(Entity).filter(Entity.display_name == "Devraj Malhotra").one()
        ccase = db.query(Case).filter(Case.actor_id == comp.id).one()
        ccase = recompute_case(db, ccase)

        # Re-fetch Arjun BEFORE-edit profile by checking ordering on fresh seed values
        # (we already mutated Arjun's ledger — use printed seed numbers + post-edit)
        print(
            f"Priya residual={pcase.residual_risk:.1f} | "
            f"Devraj residual={ccase.residual_risk:.1f} | "
            f"Arjun residual(before edit)={before:.1f} -> after={after:.1f}"
        )
        assert pcase.residual_risk < before, (
            "Priya should have lower residual risk than Arjun (pre-edit partial case)"
        )
        assert before < ccase.residual_risk, (
            "Arjun (partial) should sit below fully unexplained Devraj"
        )
        assert ccase.residual_risk >= 60, (
            f"Devraj residual_risk should be high, got {ccase.residual_risk}"
        )
        assert pcase.residual_risk <= 35, (
            f"Priya residual_risk should be relatively low, got {pcase.residual_risk}"
        )
        assert before >= 25, (
            f"Arjun pre-edit residual should reflect unexplained critical access, got {before}"
        )
        print("PASS: scenario risk ordering looks correct.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
