import os
from app import create_app, db

app = create_app()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
