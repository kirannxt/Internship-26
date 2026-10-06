from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, session
)
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User

auth = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("scanner.dashboard"))

    error = None
    is_loading = False

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password   = request.form.get("password", "")
        remember   = bool(request.form.get("remember"))

        # --- field-level validation ---
        if not identifier or not password:
            error = "Email / username and password are required."
        else:
            # try matching by email first, then username
            user = User.query.filter(
                (User.email == identifier) | (User.username == identifier)
            ).first()

            if user is None or not user.check_password(password):
                error = "Invalid credentials. Please try again."
            elif not user.is_active:
                error = "This account has been disabled."
            else:
                login_user(user, remember=remember)
                # honour ?next= redirect, but only for relative paths
                next_page = request.args.get("next")
                if next_page and next_page.startswith("/"):
                    return redirect(next_page)
                return redirect(url_for("scanner.dashboard"))

    return render_template("auth/login.html",
                           title="Sign In",
                           error=error)


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
@auth.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("scanner.dashboard"))

    errors = {}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # --- validation ---
        if not username or len(username) < 3:
            errors["username"] = "Username must be at least 3 characters."
        if not email or "@" not in email:
            errors["email"] = "A valid email address is required."
        if len(password) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if password != confirm:
            errors["confirm_password"] = "Passwords do not match."

        if not errors:
            if User.query.filter_by(email=email).first():
                errors["email"] = "An account with this email already exists."
            if User.query.filter_by(username=username).first():
                errors["username"] = "This username is already taken."

        if not errors:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully. Please sign in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html",
                           title="Create Account",
                           errors=errors,
                           form_data=request.form)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
