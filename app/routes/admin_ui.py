import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from flask_login import login_required, current_user
from app import db
from app.models.api_key import ApiKey, ApiKeyDomainAllowlist, ApiKeyIpAllowlist
from app.models.audit_log import AuditLog
from app.models.pdns_admin import PdnsDomain
from app.services.auth_service import AuthService

bp = Blueprint("admin_ui", __name__)


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


# ── Dashboard ─────────────────────────────────────────────────────────────────

@bp.route("/admin/")
@bp.route("/admin")
@login_required
@_require_admin
def dashboard():
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template("admin/dashboard.html", keys=keys)


# ── Create key ────────────────────────────────────────────────────────────────

@bp.route("/admin/keys/new", methods=["GET", "POST"])
@login_required
@_require_admin
def key_create():
    domains = PdnsDomain.query.order_by(PdnsDomain.name).all()
    csrf = _csrf_token()

    if request.method == "POST":
        if not _check_csrf():
            return render_template("admin/key_create.html", domains=domains, csrf=csrf)

        description = request.form.get("description", "").strip()
        pdns_user_id = request.form.get("pdns_user_id", "").strip()
        domain_ids = request.form.getlist("domain_ids", type=int)
        ip_addresses = [
            ip.strip() for ip in request.form.get("ip_addresses", "").splitlines()
            if ip.strip()
        ]

        if not pdns_user_id or not pdns_user_id.isdigit():
            flash("Vul een geldig PowerDNS-Admin gebruiker ID in.", "danger")
            return render_template("admin/key_create.html", domains=domains, csrf=csrf)

        full_key, key_hash, key_prefix = AuthService.generate_api_key()

        new_key = ApiKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            description=description,
            pdns_user_id=int(pdns_user_id),
            created_by=current_user.id,
        )
        db.session.add(new_key)
        db.session.flush()

        for domain_id in domain_ids:
            db.session.add(ApiKeyDomainAllowlist(api_key_id=new_key.id, domain_id=domain_id))

        for ip_line in ip_addresses:
            if "/" in ip_line:
                parts = ip_line.split("/", 1)
                db.session.add(ApiKeyIpAllowlist(
                    api_key_id=new_key.id,
                    ip_address=parts[0],
                    cidr_mask=int(parts[1])
                ))
            else:
                db.session.add(ApiKeyIpAllowlist(
                    api_key_id=new_key.id,
                    ip_address=ip_line,
                    cidr_mask=None
                ))

        db.session.commit()

        # Show the full key exactly once via flash
        flash(f"API key aangemaakt. Bewaar deze key — hij is maar één keer zichtbaar: {full_key}", "key")
        return redirect(url_for("admin_ui.key_detail", key_id=new_key.id))

    return render_template("admin/key_create.html", domains=domains, csrf=csrf)


# ── Key detail / edit ─────────────────────────────────────────────────────────

@bp.route("/admin/keys/<int:key_id>")
@login_required
@_require_admin
def key_detail(key_id):
    key = db.get_or_404(ApiKey, key_id)
    domains_allowed = key.domain_allowlist.all()
    allowed_domain_ids = {d.domain_id for d in domains_allowed}
    all_domains = PdnsDomain.query.order_by(PdnsDomain.name).all()
    ips = key.ip_allowlist.all()
    csrf = _csrf_token()
    return render_template(
        "admin/key_detail.html",
        key=key,
        domains_allowed=domains_allowed,
        allowed_domain_ids=allowed_domain_ids,
        all_domains=all_domains,
        ips=ips,
        csrf=csrf,
    )


@bp.route("/admin/keys/<int:key_id>/toggle", methods=["POST"])
@login_required
@_require_admin
def key_toggle(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    key = db.get_or_404(ApiKey, key_id)
    key.is_active = not key.is_active
    db.session.commit()
    state = "geactiveerd" if key.is_active else "ingetrokken"
    flash(f"Key {key.key_prefix}… is {state}.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/admin/keys/<int:key_id>/edit", methods=["POST"])
@login_required
@_require_admin
def key_edit(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    key = db.get_or_404(ApiKey, key_id)
    key.description = request.form.get("description", "").strip()
    db.session.commit()
    flash("Omschrijving opgeslagen.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/admin/keys/<int:key_id>/delete", methods=["POST"])
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


# ── Domain allowlist ──────────────────────────────────────────────────────────

@bp.route("/admin/keys/<int:key_id>/domains/add", methods=["POST"])
@login_required
@_require_admin
def domain_add(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    db.get_or_404(ApiKey, key_id)
    domain_id = request.form.get("domain_id", type=int)
    if not domain_id:
        flash("Selecteer een domein.", "danger")
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    if not ApiKeyDomainAllowlist.query.filter_by(api_key_id=key_id, domain_id=domain_id).first():
        db.session.add(ApiKeyDomainAllowlist(api_key_id=key_id, domain_id=domain_id))
        db.session.commit()
        flash("Domein toegevoegd.", "success")
    else:
        flash("Domein stond al in de allowlist.", "warning")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/admin/keys/<int:key_id>/domains/<int:domain_id>/remove", methods=["POST"])
@login_required
@_require_admin
def domain_remove(key_id, domain_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    entry = ApiKeyDomainAllowlist.query.filter_by(
        api_key_id=key_id, domain_id=domain_id
    ).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    flash("Domein verwijderd.", "info")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


# ── IP allowlist ──────────────────────────────────────────────────────────────

@bp.route("/admin/keys/<int:key_id>/ips/add", methods=["POST"])
@login_required
@_require_admin
def ip_add(key_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    db.get_or_404(ApiKey, key_id)
    ip_address = request.form.get("ip_address", "").strip()
    cidr_mask = request.form.get("cidr_mask", "").strip() or None
    if not ip_address:
        flash("Vul een IP adres in.", "danger")
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    db.session.add(ApiKeyIpAllowlist(
        api_key_id=key_id,
        ip_address=ip_address,
        cidr_mask=int(cidr_mask) if cidr_mask else None
    ))
    db.session.commit()
    flash("IP toegevoegd.", "success")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


@bp.route("/admin/keys/<int:key_id>/ips/<int:ip_id>/remove", methods=["POST"])
@login_required
@_require_admin
def ip_remove(key_id, ip_id):
    if not _check_csrf():
        return redirect(url_for("admin_ui.key_detail", key_id=key_id))
    entry = ApiKeyIpAllowlist.query.filter_by(id=ip_id, api_key_id=key_id).first_or_404()
    db.session.delete(entry)
    db.session.commit()
    flash("IP verwijderd.", "info")
    return redirect(url_for("admin_ui.key_detail", key_id=key_id))


# ── Audit log ─────────────────────────────────────────────────────────────────

@bp.route("/admin/keys/<int:key_id>/audit")
@login_required
@_require_admin
def key_audit(key_id):
    key = db.get_or_404(ApiKey, key_id)
    page = request.args.get("page", 1, type=int)
    logs = AuditLog.query.filter_by(api_key_id=key_id)\
        .order_by(AuditLog.timestamp.desc())\
        .paginate(page=page, per_page=50)
    return render_template("admin/key_audit.html", key=key, logs=logs)
