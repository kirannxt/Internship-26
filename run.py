import os
from app import create_app, db
from app.models import User, ScanHistory

app = create_app()


def seed_demo_user():
    """
    Creates a demo user on first run so the app is immediately usable.
    Credentials:  demo@phishguard.io  /  demo1234
    Safe to run repeatedly — skips if the user already exists.
    """
    existing = User.query.filter_by(email="demo@phishguard.io").first()
    if existing:
        return

    demo = User(username="demo", email="demo@phishguard.io")
    demo.set_password("demo1234")
    db.session.add(demo)
    db.session.commit()
    print("[seed] Demo user created → demo@phishguard.io / demo1234")


if __name__ == "__main__":
    with app.app_context():
        # Create all tables (no-op if they already exist)
        db.create_all()
        print("[db] Tables verified / created.")

        # Seed demo data
        seed_demo_user()

    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    print(f"[app] Starting PhishGuard on http://localhost:{port}  (debug={debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)
