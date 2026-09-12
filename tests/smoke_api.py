"""API smoke check via TestClient."""

from fastapi.testclient import TestClient

from database import init_db
from main import app
from seed.scenarios import clear_all, run_seed
from database import SessionLocal

init_db()
db = SessionLocal()
try:
    clear_all(db)
    run_seed(db)
finally:
    db.close()

with TestClient(app) as c:
    r = c.get("/entities")
    print("entities", r.status_code, len(r.json()))

    cases = c.get("/cases").json()
    print(
        "cases",
        [
            (
                x["actor_name"],
                round(x["residual_risk"], 1),
                round(x["context_coverage"], 2),
            )
            for x in cases
        ],
    )

    arjun = next(x for x in cases if x["actor_name"] == "Arjun")
    d = c.get(f"/cases/{arjun['id']}").json()
    print(
        "arjun breakdown",
        [
            (b["resource_id"], b["status"])
            for b in d["explanation_breakdown"]
            if b.get("resource_id")
        ],
    )
    print("counterfactual", c.get(f"/cases/{arjun['id']}/counterfactual").status_code)
    print("shiftmap", c.get(f"/cases/{arjun['id']}/shift-map-data").status_code)
    print("context", c.get(f"/entities/{arjun['actor_id']}/context").status_code)
    print("events", c.get(f"/entities/{arjun['actor_id']}/events").status_code)
    print("OK")
