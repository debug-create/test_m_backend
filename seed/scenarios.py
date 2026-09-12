"""
Seed data for three demo scenarios.

IMPORTANT: We tune INPUT DATA (events, volumes, timing, context entries) until
the real modules 2–6 produce the target risk profile. We never special-case
the calculation modules per named actor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from engine.case_builder import create_or_update_case, recompute_case, select_unusual_events
from engine.context import evaluate_context_compatibility
from models.db_models import Case, CohortThreshold, ContextLedgerEntry, Entity, Event


EPOCH = datetime(2026, 8, 1, 9, 0, 0, tzinfo=timezone.utc)


def _e(
    actor_id: int,
    day_offset: float,
    hour: int,
    action: str,
    device: str,
    resource: str | None = None,
    classification: str | None = "internal",
    destination: str | None = None,
    volume: int | None = None,
    result: str = "success",
) -> dict:
    ts = EPOCH + timedelta(days=day_offset, hours=hour - 9)
    return dict(
        timestamp=ts,
        actor_id=actor_id,
        device_id=device,
        action=action,
        resource_id=resource,
        resource_classification=classification,
        destination=destination,
        volume=volume,
        result=result,
    )


def _add_events(db: Session, rows: list[dict]) -> list[Event]:
    events = []
    for r in rows:
        ev = Event(**r)
        db.add(ev)
        events.append(ev)
    db.flush()
    return events


def _baseline_engineering(
    actor_id: int, device: str, days: int = 28, start_day: float = 0
) -> list[dict]:
    """Normal engineering daily pattern: morning login, repo/file access, modest downloads."""
    rows = []
    for d in range(days):
        day = start_day + d
        # Skip weekends roughly
        if int(day) % 7 in (5, 6):
            continue
        rows.append(_e(actor_id, day, 9, "login", device))
        rows.append(
            _e(
                actor_id,
                day,
                10,
                "repo_access",
                device,
                "eng-main-repo",
                "internal",
            )
        )
        rows.append(
            _e(
                actor_id,
                day,
                11,
                "file_access",
                device,
                "eng-docs",
                "internal",
            )
        )
        if d % 3 == 0:
            rows.append(
                _e(
                    actor_id,
                    day,
                    14,
                    "file_download",
                    device,
                    "eng-docs",
                    "internal",
                    volume=40 + (d % 5) * 5,
                )
            )
        rows.append(
            _e(
                actor_id,
                day,
                16,
                "repo_access",
                device,
                "eng-main-repo",
                "internal",
            )
        )
    return rows


def _baseline_peers(db: Session) -> None:
    """Peer entities in same roles so cohort baselines are meaningful."""
    peers = [
        ("Dev Peer A", "engineering", "Engineering", -60),
        ("Dev Peer B", "engineering", "Engineering", -60),
        ("Dev Peer C", "engineering", "Engineering", -55),
        ("Sec Peer A", "security", "Security", -90),
        ("Sec Peer B", "security", "Security", -80),
        ("Sec Peer C", "security", "Security", -70),
        ("Fin Peer A", "finance", "Finance", -100),
        ("Fin Peer B", "finance", "Finance", -95),
        ("Fin Peer C", "finance", "Finance", -90),
    ]
    for name, role, dept, hire_off in peers:
        ent = Entity(
            display_name=name,
            role=role,
            department=dept,
            hire_date=EPOCH + timedelta(days=hire_off),
        )
        db.add(ent)
        db.flush()
        device = f"{name.lower().replace(' ', '-')}-laptop"
        if role == "engineering":
            rows = _baseline_engineering(ent.id, device, days=30, start_day=0)
        elif role == "security":
            rows = []
            for d in range(30):
                if d % 7 in (5, 6):
                    continue
                rows.append(_e(ent.id, d, 8, "login", device))
                rows.append(
                    _e(
                        ent.id,
                        d,
                        9,
                        "file_access",
                        device,
                        "sec-tooling",
                        "restricted",
                    )
                )
                rows.append(
                    _e(
                        ent.id,
                        d,
                        11,
                        "repo_access",
                        device,
                        "sec-playbooks",
                        "restricted",
                    )
                )
                if d % 4 == 0:
                    rows.append(
                        _e(
                            ent.id,
                            d,
                            13,
                            "file_download",
                            device,
                            "sec-playbooks",
                            "restricted",
                            volume=30,
                        )
                    )
        else:  # finance
            rows = []
            for d in range(30):
                if d % 7 in (5, 6):
                    continue
                rows.append(_e(ent.id, d, 9, "login", device))
                rows.append(
                    _e(
                        ent.id,
                        d,
                        10,
                        "file_access",
                        device,
                        "finance-archive",
                        "critical",
                    )
                )
                rows.append(
                    _e(
                        ent.id,
                        d,
                        12,
                        "file_download",
                        device,
                        "finance-archive",
                        "critical",
                        volume=20,
                    )
                )
        _add_events(db, rows)

    for role in ("engineering", "security", "finance"):
        db.add(CohortThreshold(role=role, threshold=40.0))
    db.flush()


def seed_priya(db: Session) -> Entity:
    """
    Priya: Engineering → Security, legitimate role change.
    Target: low residual risk after context is applied.
    """
    priya = Entity(
        display_name="Priya",
        role="security",  # current role after transition
        department="Security",
        hire_date=EPOCH - timedelta(days=200),
    )
    db.add(priya)
    db.flush()

    device = "priya-laptop"
    # Days 0–20: normal engineering baseline
    rows = _baseline_engineering(priya.id, device, days=21, start_day=0)

    # Role change context starting day 21 (~ week 3)
    ctx = ContextLedgerEntry(
        actor_id=priya.id,
        reason="role_change",
        valid_from=EPOCH + timedelta(days=21),
        valid_until=EPOCH + timedelta(days=90),
        allowed_resources=["sec-tooling", "sec-playbooks", "sec-incident-queue"],
        allowed_actions=[
            "login",
            "file_access",
            "repo_access",
            "file_download",
            "privilege_change",
            "permission_request",
        ],
        approved_destinations=None,
        approved_by="hr-ops",
    )
    db.add(ctx)
    db.flush()

    # Days 21–35: security-like activity fully within context
    for d in range(21, 36):
        if d % 7 in (5, 6):
            continue
        rows.append(_e(priya.id, d, 8, "login", device))
        rows.append(
            _e(
                priya.id,
                d,
                9,
                "file_access",
                device,
                "sec-tooling",
                "restricted",
            )
        )
        rows.append(
            _e(
                priya.id,
                d,
                11,
                "repo_access",
                device,
                "sec-playbooks",
                "restricted",
            )
        )
        if d % 3 == 0:
            rows.append(
                _e(
                    priya.id,
                    d,
                    14,
                    "file_download",
                    device,
                    "sec-playbooks",
                    "restricted",
                    volume=50,
                )
            )
        if d == 22:
            rows.append(
                _e(
                    priya.id,
                    d,
                    10,
                    "privilege_change",
                    device,
                    "sec-tooling",
                    "restricted",
                )
            )

    events = _add_events(db, rows)

    # Build case from transition window (day 21–25 unusual relative to eng history)
    as_of = EPOCH + timedelta(days=35, hours=18)
    transition = [
        e
        for e in events
        if EPOCH + timedelta(days=21) <= e.timestamp <= EPOCH + timedelta(days=25)
    ]
    lookback = [e for e in events if e.timestamp < EPOCH + timedelta(days=21)]
    unusual = select_unusual_events(transition, lookback)
    case = create_or_update_case(
        db,
        priya.id,
        unusual,
        change_points=[(EPOCH + timedelta(days=21, hours=8)).isoformat()],
        as_of=as_of,
    )
    return priya


def seed_compromised(db: Session) -> Entity:
    """
    Devraj Malhotra: abrupt anomalous burst, NO context.
    Target: high residual risk.
    """
    acct = Entity(
        display_name="Devraj Malhotra",
        role="engineering",
        department="Engineering",
        hire_date=EPOCH - timedelta(days=400),
    )
    db.add(acct)
    db.flush()

    device = "compromised-laptop"
    rows = _baseline_engineering(acct.id, device, days=28, start_day=0)

    # Day 29: tight malicious cluster — new device, privilege, sensitive, download
    attack_device = "unknown-vps-77"
    day = 29
    rows.append(_e(acct.id, day, 2, "login", attack_device))  # irregular hour
    rows.append(
        _e(
            acct.id,
            day,
            2,
            "privilege_change",
            attack_device,
            "admin-panel",
            "critical",
        )
    )
    rows.append(
        _e(
            acct.id,
            day,
            3,
            "file_access",
            attack_device,
            "finance-archive",
            "critical",
        )
    )
    rows.append(
        _e(
            acct.id,
            day,
            3,
            "file_access",
            attack_device,
            "hr-salaries",
            "critical",
        )
    )
    rows.append(
        _e(
            acct.id,
            day,
            4,
            "file_download",
            attack_device,
            "finance-archive",
            "critical",
            volume=5000,
        )
    )
    rows.append(
        _e(
            acct.id,
            day,
            4,
            "external_upload",
            attack_device,
            "finance-archive",
            "critical",
            destination="http://exfil.evil.example/drop",
            volume=5000,
        )
    )

    events = _add_events(db, rows)
    as_of = EPOCH + timedelta(days=29, hours=6)
    attack_events = [
        e
        for e in events
        if e.timestamp >= EPOCH + timedelta(days=29)
    ]
    case = create_or_update_case(
        db,
        acct.id,
        attack_events,
        change_points=[(EPOCH + timedelta(days=29, hours=2)).isoformat()],
        as_of=as_of,
    )
    return acct


def seed_sparse_new_hire(db: Session) -> Entity:
    """New actor with too little history for a determinate assessment."""
    actor = Entity(
        display_name="Neha (New Hire)",
        role="engineering",
        department="Engineering",
        hire_date=EPOCH + timedelta(days=38),
    )
    db.add(actor)
    db.flush()

    rows = [
        _e(actor.id, 40, 9, "login", "neha-laptop"),
        _e(actor.id, 41, 9, "login", "neha-laptop"),
        _e(
            actor.id,
            42,
            11,
            "file_access",
            "neha-laptop",
            "new-team-share",
            None,
        ),
    ]
    events = _add_events(db, rows)
    case = create_or_update_case(
        db,
        actor.id,
        events,
        change_points=[],
        as_of=EPOCH + timedelta(days=42, hours=12),
    )
    return actor


def seed_arjun(db: Session) -> Entity:
    """
    Arjun: partial explanation.
    Context allows migration-repo only.
    (a) migration-repo access → explained
    (b) finance-archive + external upload → unexplained
    """
    arjun = Entity(
        display_name="Arjun",
        role="engineering",
        department="Engineering",
        hire_date=EPOCH - timedelta(days=300),
    )
    db.add(arjun)
    db.flush()

    device = "arjun-laptop"
    rows = _baseline_engineering(arjun.id, device, days=25, start_day=0)

    ctx = ContextLedgerEntry(
        actor_id=arjun.id,
        reason="project",
        valid_from=EPOCH + timedelta(days=25),
        valid_until=EPOCH + timedelta(days=45),
        allowed_resources=["migration-repo"],
        allowed_actions=[
            "login",
            "repo_access",
            "file_access",
            "file_download",
        ],
        approved_destinations=["s3://corp-migration-backup"],
        approved_by="eng-manager",
    )
    db.add(ctx)
    db.flush()

    day = 26
    # (a) Legitimate migration work
    rows.append(_e(arjun.id, day, 9, "login", device))
    rows.append(
        _e(
            arjun.id,
            day,
            10,
            "repo_access",
            device,
            "migration-repo",
            "internal",
        )
    )
    rows.append(
        _e(
            arjun.id,
            day,
            11,
            "repo_access",
            device,
            "migration-repo",
            "internal",
        )
    )
    rows.append(
        _e(
            arjun.id,
            day,
            12,
            "file_download",
            device,
            "migration-repo",
            "internal",
            volume=800,
        )
    )
    rows.append(
        _e(
            arjun.id,
            day,
            13,
            "file_access",
            device,
            "migration-repo",
            "internal",
        )
    )

    # (b) Unexplained: finance archive + external upload not in context
    rows.append(
        _e(
            arjun.id,
            day,
            15,
            "file_access",
            device,
            "finance-archive",
            "critical",
        )
    )
    rows.append(
        _e(
            arjun.id,
            day,
            16,
            "file_download",
            device,
            "finance-archive",
            "critical",
            volume=2000,
        )
    )
    rows.append(
        _e(
            arjun.id,
            day,
            17,
            "external_upload",
            device,
            "finance-archive",
            "critical",
            destination="https://personal-cloud.example/upload",
            volume=2000,
        )
    )

    events = _add_events(db, rows)
    as_of = EPOCH + timedelta(days=26, hours=20)
    transition = [
        e
        for e in events
        if e.timestamp >= EPOCH + timedelta(days=25)
    ]
    case = create_or_update_case(
        db,
        arjun.id,
        transition,
        change_points=[(EPOCH + timedelta(days=26, hours=9)).isoformat()],
        as_of=as_of,
    )

    # Verify per-event breakdown
    breakdown = evaluate_context_compatibility(db, arjun.id, transition)
    print(f"    counts={breakdown['counts']}")
    for b in breakdown["breakdown"]:
        print(
            f"    event {b['event_id']} {b['action']} "
            f"{b['resource_id'] or b['destination']}: {b['status']}"
        )
    return arjun


def run_seed(db: Session) -> None:
    print("Seeding peer baselines...")
    _baseline_peers(db)
    print("Seeding Priya...")
    seed_priya(db)
    print("Seeding Devraj Malhotra...")
    seed_compromised(db)
    print("Seeding Arjun...")
    seed_arjun(db)
    print("Seeding sparse-history demo actor...")
    seed_sparse_new_hire(db)
    # Recompute after every actor is present so cohort-derived seed snapshots do
    # not depend on insertion order.
    for case in db.query(Case).order_by(Case.id.asc()).all():
        case = recompute_case(db, case)
        actor = db.query(Entity).filter(Entity.id == case.actor_id).one()
        print(
            f"  {actor.display_name} case #{case.id}: raw={case.raw_deviation:.1f} "
            f"coverage={case.context_coverage:.2f} residual={case.residual_risk:.1f} "
            f"data_quality={case.data_quality} "
            f"unresolved={case.residual_unresolved_count}"
        )
    db.commit()
    print("Seed complete.")


def clear_all(db: Session) -> None:
    from models.db_models import AnalystFeedback

    # Delete in FK-safe order
    db.query(AnalystFeedback).delete()
    db.query(Case).delete()
    db.query(Event).delete()
    db.query(ContextLedgerEntry).delete()
    db.query(CohortThreshold).delete()
    db.query(Entity).delete()
    db.commit()
