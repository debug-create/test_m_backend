"""End-to-end API checks using an isolated in-memory database."""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.routes import router
from database import Base, get_db
from seed.scenarios import run_seed


def test_context_edit_counterfactual_and_auto_reopen_end_to_end():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    run_seed(session)

    app = FastAPI()
    app.include_router(router)

    def override_db():
        yield session

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        arjun = next(
            item for item in client.get("/entities").json()
            if item["display_name"] == "Arjun"
        )
        case = next(
            item for item in client.get("/cases").json()
            if item["actor_id"] == arjun["id"]
        )
        before = client.get(f"/cases/{case['id']}").json()
        context = client.get(f"/entities/{arjun['id']}/context").json()[0]
        context["allowed_resources"] = context["allowed_resources"] + ["finance-archive"]
        context["allowed_actions"] = context["allowed_actions"] + ["external_upload"]
        context["approved_destinations"] = context["approved_destinations"] + [
            "https://personal-cloud.example/upload"
        ]
        response = client.post(f"/entities/{arjun['id']}/context", json=context)
        assert response.status_code == 200

        after = client.get(f"/cases/{case['id']}").json()
        assert after["raw_deviation"] == before["raw_deviation"]
        assert after["residual_risk"] < before["residual_risk"]
        assert after["context_coverage"] > before["context_coverage"]

        counterfactual = client.get(
            f"/cases/{case['id']}/counterfactual"
        ).json()
        context_alt = next(
            item for item in counterfactual["components"]
            if item["component"] == "context"
        )
        assert context_alt["residual_risk_without"] == after["raw_deviation"]
        assert context_alt["delta"] != 0.0

        feedback = client.post(
            f"/cases/{case['id']}/feedback",
            json={"verdict": "authorized", "notes": "Grant confirmed."},
        )
        assert feedback.status_code == 200
        assert feedback.json()["case_status"] == "resolved"
        assert client.get(f"/cases/{case['id']}").json()["status"] == "resolved"

        outside = client.post(
            f"/entities/{arjun['id']}/events",
            json={
                "timestamp": "2026-08-28T10:00:00Z",
                "device_id": "arjun-laptop",
                "action": "file_access",
                "resource_id": "payroll-private",
                "resource_classification": "critical",
                "result": "success",
            },
        )
        assert outside.status_code == 201
        assert client.get(f"/cases/{case['id']}").json()["status"] == "reopened"

    session.close()
