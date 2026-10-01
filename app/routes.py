from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db
from app.models import User

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return render_template("index.html", title="Home")


@main.route("/about")
def about():
    return render_template("about.html", title="About")


@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # TODO: implement login logic
        flash("Login functionality coming soon.", "info")
        return redirect(url_for("main.index"))
    return render_template("login.html", title="Login")


@main.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # TODO: implement registration logic
        flash("Registration functionality coming soon.", "info")
        return redirect(url_for("main.index"))
    return render_template("register.html", title="Register")
