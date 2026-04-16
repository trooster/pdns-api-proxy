import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app.models.pdns_admin import PdnsUser

bp = Blueprint("auth", __name__)


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _check_csrf():
    token = request.form.get("csrf_token", "")
    if not secrets.compare_digest(token, session.get("csrf_token", "")):
        flash("Invalid request (CSRF). Please try again.", "danger")
        return False
    return True


@bp.route("/admin/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_ui.dashboard"))

    csrf = _csrf_token()

    if request.method == "POST":
        if not _check_csrf():
            return redirect(url_for("auth.login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = PdnsUser.query.filter_by(username=username).first()

        if not user or not user.verify_password(password):
            flash("Ongeldige gebruikersnaam of wachtwoord.", "danger")
            return render_template("admin/login.html", csrf=csrf)

        if not user.is_admin:
            flash("Je hebt geen beheerdersrechten.", "danger")
            return render_template("admin/login.html", csrf=csrf)

        if user.has_2fa:
            # Store user id temporarily; complete login after 2FA
            session["pending_user_id"] = user.id
            return redirect(url_for("auth.login_2fa"))

        login_user(user, remember=False)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("admin_ui.dashboard"))

    return render_template("admin/login.html", csrf=csrf)


@bp.route("/admin/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    csrf = _csrf_token()

    if request.method == "POST":
        if not _check_csrf():
            return redirect(url_for("auth.login_2fa"))

        code = request.form.get("code", "").strip().replace(" ", "")
        user = PdnsUser.query.get(pending_id)

        if not user or not user.verify_totp(code):
            flash("Ongeldige 2FA code.", "danger")
            return render_template("admin/login_2fa.html", csrf=csrf)

        session.pop("pending_user_id", None)
        login_user(user, remember=False)
        return redirect(url_for("admin_ui.dashboard"))

    return render_template("admin/login_2fa.html", csrf=csrf)


@bp.route("/admin/logout")
@login_required
def logout():
    logout_user()
    flash("Je bent uitgelogd.", "info")
    return redirect(url_for("auth.login"))
