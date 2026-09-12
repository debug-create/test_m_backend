"""CLI: python -m seed.run_seed"""

from database import SessionLocal, init_db
from seed.scenarios import clear_all, run_seed


def main():
    init_db()
    db = SessionLocal()
    try:
        clear_all(db)
        run_seed(db)
    finally:
        db.close()


if __name__ == "__main__":
    main()
