import ipaddress
import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_login import login_required, current_user
from markupsafe import Markup, escape as _escape
from sqlalchemy import func
from app import db
from app.models.api_key import ApiKey, ApiKeyIpAllowlist
from app.models.audit_log import AuditLog
from app.models.pdns_admin import PdnsAccount, PdnsDomain, PdnsUser, PdnsAccountUser
from app.services.auth_service import AuthService

bp = Blueprint("admin_ui", __name__)


# ── Access helpers ─────────────────────────────────────────────────────────────

def _get_accessible_accounts():
    """Admins zien alle accounts; gewone gebruikers alleen hun eigen accounts."""
    if current_user.is_admin:
        return PdnsAccount.query.order_by(PdnsAccount.name).all()
    account_ids = [
        row[0] for row in
        db.session.query(PdnsAccountUser.account_id)
        .filter(PdnsAccountUser.user_id == current_user.id)
        .all()
    ]
    if not account_ids:
        return []
    return PdnsAccount.query.filter(PdnsAccount.id.in_(account_ids)).order_by(PdnsAccount.name).all()


def _check_key_access(key_id):
    """Geeft de key terug. Voor niet-admins: abort(403) als de key niet bij hun account hoort."""
    key = db.get_or_404(ApiKey, key_id)
    if not current_user.is_admin:
        accessible_ids = [a.id for a in _get_accessible_accounts()]
        if key.account_id not in accessible_ids:
            abort(403)
    return key


def _require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _check_csrf():
    token = request.form.get("csrf_token", "")
    if not secrets.compare_digest(token, session.get("csrf_token", "")):
        flash("Ongeldige CSRF token. Probeer opnieuw.", "danger")
        return False
    return True


def _parse_ip_entry(ip_line: str):
    """
    Parses 'IP' or 'IP/mask' and returns (ip_str, cidr_mask).
    Bare IPs get /32 (IPv4) or /128 (IPv6) as default mask.
    Raises ValueError on invalid input.
    """
    ip_line = ip_line.strip()
    if "/" in ip_line:
        ip_str, mask_str = ip_line.split("/", 1)
        ip_str = ip_str.strip()
        mask = int(mask_str.strip())
    else:
        ip_str = ip_line
        addr = ipaddress.ip_address(ip_str)
        mask = 32 if addr.version == 4 else 128
    # Validate the IP address
    ipaddress.ip_address(ip_str)
    return ip_str, mask


# ── Dashboard ─────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
def dashboard():
    accounts = _get_accessible_accounts()
    account_ids = [a.id for a in accounts]

    if account_ids:
        keys = ApiKey.query.filter(ApiKey.account_id.in_(account_ids))\
            .order_by(ApiKey.created_at.desc()).all()
    else:
        keys = []
    key_ids = [k.id for k in keys]

    domain_counts = {}
    if account_ids:
        for account_id, count in db.session.query(PdnsDomain.account_id, func.count(PdnsDomain.id))\
                .filter(PdnsDomain.account_id.in_(account_ids))\
                .group_by(PdnsDomain.account_id):
            domain_counts[account_id] = count

    last_used = {}
    request_counts = {}
    if key_ids:
        for key_id, ts, cnt in db.session.query(
                AuditLog.api_key_id,
                func.max(AuditLog.timestamp),
                func.count(AuditLog.id))\
                .filter(AuditLog.api_key_id.in_(key_ids))\
                .group_by(AuditLog.api_key_id):
            last_used[key_id] = ts
            request_counts[key_id] = cnt

    ip_counts = {}
    if key_ids:
        for key_id, count in db.session.query(ApiKeyIpAllowlist.api_key_id, func.count(ApiKeyIpAllowlist.id))\
                .filter(ApiKeyIpAllowlist.api_key_id.in_(key_ids))\
                .group_by(ApiKeyIpAllowlist.api_key_id):
            ip_counts[key_id] = count

    return render_template("admin/dashboard.html", keys=keys, accounts={a.id: a for a in accounts},
                           domain_counts=domain_counts, last_used=last_used,
                           ip_counts=ip_counts, request_counts=request_counts,
                           has_accounts=bool(account_ids))


# ── Create key ────────────────────────────────────────────────────────────────

@bp.route("/keys/new", methods=["GET", "POST"])
@login_required
def key_create():
    accounts = _get_accessible_accounts()
    csrf = _csrf_token()

    if request.method == "POST":
        if not _check_csrf():
            return render_template("admin/key_create.html", accounts=accounts, csrf=csrf)

        description = request.form.get("description", "").strip()
        account_id_str = request.form.get("account_id", "").strip()
        ip_addresses = [
            ip.strip() for ip in request.form.get("ip_addresses", "").splitlines()
            if ip.strip()
        ]

        if not account_id_str or not account_id_str.isdigit():
            flash("Selecteer een account.", "danger")
            return render_template("admin/key_create.html", accounts=accounts, csrf=csrf)

        account_id = int(account_id_str)
        # Security: verify the selected account is accessible to this user
        if account_id not in [a.id for a in accounts]:
            abort(403)

        full_key, key_hash, key_prefix = AuthService.generate_api_key()

        new_key = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            description=description,
            account_id=account_id,
            created_by=current_user.id,
        )
        db.session.add(new_key)
        db.session.flush()

        for ip_line in ip_addresses:
            try:
                ip_str, cidr_mask = _parse_ip_entry(ip_line)
            except ValueError:
                flash(Markup("Ongeldig IP adres: {}").format(_escape(ip_line)), "danger")
                db.session.rollback()
                return render_template("admin/key_create.html", accounts=accounts, csrf=csrf)
            db.session.add(ApiKeyIpAllowlist(
                api_key_id=new_key.id,
                ip_address=ip_str,
                cidr_mask=cidr_mask,
            ))

        db.session.commit()

        # Show the full key exactly once via flash
        flash(f"API key aangemaakt. Bewaar deze key — hij is maar één keer zichtbaar: {full_key}", "key")
        return redirect(url_for("admin_ui.key_detail", key_id=new_key.id))

    return render_template("admin/key_create.html", accounts=accounts, csrf=csrf)


# ── Account domains (AJAX) ────────────────────────────────────────────────────

@bp.route("/accounts/<int:account_id>/domains")
@login_required
def account_domains(account_id):
    if not current_user.is_admin:
        accessible_ids = [a.id for a in _get_accessible_accounts()]
        if account_id not in accessible_ids:
            abort(403)
    account = PdnsAccount.query.get_or_404(account_id)
    domains = [{"id": d.id, "name": d.name} for d in account.domains.order_by(PdnsDomain.name)]
    return jsonify({"account": account.name, "domains": domains})


# ── Key detail / edit ─────────────────────────────────────────────────────────

@bp.route("/keys/<int:key_id>")
@login_required
def key_detail(key_id):
    key = _check_key_access(key_id)
    account = db.session.get(PdnsAccount, key.account_id)
    ips = key.ip_allowlist.all()
    domains = account.domains.order_by(PdnsDomain.name).all() if account else []
    created_by_user = db.session.get(PdnsUser, key.created_by) if key.created_by else None
    csrf = _csrf_token()
    return render_template(
        "admin/key_detail.html",
        key=key,
        account=account,
        ips=ips,
        domains=domains,
        created_by_user=created_by_user,
        csrf=csrf,
    )


@bp.route("/keys/<int:key_id>/toggle", methods=["POST"])
@login_required
def key_toggle(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    key = _check_key_access(key_id)
    key.is_active = not key.is_active
    db.session.commit()
    state = "geactiveerd" if key.is_active else "ingetrokken"
    flash(f"Key {key.key_prefix}… is {state}.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/keys/<int:key_id>/edit", methods=["POST"])
@login_required
def key_edit(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    key = _check_key_access(key_id)
    key.description = request.form.get("description", "").strip()
    db.session.commit()
    flash("Omschrijving opgeslagen.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/keys/<int:key_id>/delete", methods=["POST"])
@login_required
@_require_admin
def key_delete(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    key = db.get_or_404(ApiKey, key_id)
    prefix = key.key_prefix
    db.session.delete(key)
    db.session.commit()
    flash(f"Key {prefix}… is verwijderd.", "info")
    return redirect(url_for("admin_ui.dashboard"))


# ── IP allowlist ──────────────────────────────────────────────────────────────

@bp.route("/keys/<int:key_id>/ips/add", methods=["POST"])
@login_required
def ip_add(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    _check_key_access(key_id)
    ip_cidr = request.form.get("ip_cidr", "").strip()
    if not ip_cidr:
        flash("Vul een IP adres in.", "danger")
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    try:
        ip_address, cidr_mask = _parse_ip_entry(ip_cidr)
    except ValueError:
        flash(Markup("Ongeldig IP adres of CIDR notatie: {}").format(_escape(ip_cidr)), "danger")
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    db.session.add(ApiKeyIpAllowlist(
        api_key_id=key_id,
        ip_address=ip_address,
        cidr_mask=cidr_mask,
    ))
    db.session.commit()
    flash("IP toegevoegd.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/keys/<int:key_id>/ips/<int:ip_id>/remove", methods=["POST"])
@login_required
def ip_remove(key_id, ip_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    _check_key_access(key_id)
    entry = ApiKeyIpAllowlist.query.filter_by(id=ip_id, api_key_id=key_id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    flash("IP verwijderd.", "info")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


# ── Audit log ─────────────────────────────────────────────────────────────────

@bp.route("/keys/<int:key_id>/audit")
@login_required
def key_audit(key_id):
    key = _check_key_access(key_id)
    page = request.args.get("page", 1, type=int)
    logs = AuditLog.query.filter_by(api_key_id=key_id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=50)
    return render_template("admin/key_audit.html", key=key, logs=logs)
