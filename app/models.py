from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """User account model."""
    __tablename__ = "users"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    is_active     = db.Column(db.Boolean, default=True)

    # Relationship to scan history
    scans = db.relationship("ScanHistory", backref="user", lazy="dynamic",
                            cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        """Hash and store the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


class ScanHistory(db.Model):
    """Stores each URL scan result per user."""
    __tablename__ = "scan_history"

    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    url           = db.Column(db.String(2048), nullable=False)
    prediction    = db.Column(db.String(32), nullable=False)   # safe | suspicious | malicious
    probability   = db.Column(db.Float, nullable=True)
    risk_level    = db.Column(db.String(16), nullable=True)    # LOW | MEDIUM | HIGH
    model_version = db.Column(db.String(32), nullable=True)
    scanned_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "url":           self.url,
            "prediction":    self.prediction,
            "probability":   self.probability,
            "risk_level":    self.risk_level,
            "model_version": self.model_version,
            "scanned_at":    self.scanned_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def __repr__(self):
        return f"<ScanHistory {self.url[:40]} → {self.prediction}>"
