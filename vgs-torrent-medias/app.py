import os
import re
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, flash, g, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from sqlalchemy import event, func
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

import config
from core.layout_sig import bind as _layout_bind
from device_guard import (
    COOKIE_NAME,
    attach_machine_cookie,
    blocked_page_context,
    ensure_machine,
    identify_device,
    parse_block_duration,
    refresh_block_state,
    register_attempt,
    with_device_cookie,
)
from email_check import verify_mailbox
from extensions import db
from hardening import (
    LOGIN_ERROR,
    add_security_headers,
    apply_proxy_fix,
    clear_password_reset,
    client_ip,
    normalize_ip,
    pending_reset_user_id,
    request_ips,
    start_password_reset,
    too_many_requests,
)
from models import (
    DeviceBlock,
    LibraryItem,
    DividerSection,
    NavDivider,
    RoleDivider,
    RoleSection,
    Section,
    User,
    ensure_schema,
    init_default_data,
)

app = Flask(__name__)
app.config.from_object(config)
apply_proxy_fix(app)
CSRFProtect(app)
_layout_bind(app)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Faça login para continuar."
login_manager.login_message_category = "error"
app.config.setdefault("SEND_FILE_MAX_AGE_DEFAULT", 120)


@event.listens_for(Engine, "connect")
def _sqlite_fast_pragmas(dbapi_connection, _connection_record):
    module = (type(dbapi_connection).__module__ or "").lower()
    name = type(dbapi_connection).__name__.lower()
    if "sqlite" not in module and "sqlite" not in name:
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


with app.app_context():
    db.create_all()
    ensure_schema()
    init_default_data()


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    if request.path.startswith("/api/"):
        return jsonify({"erro": "Sessão expirada. Recarregue a página."}), 400
    flash("Sessão expirada. Tente de novo.", "error")
    return redirect(url_for("login"))


@login_manager.user_loader
def load_user(user_id):
    raw = str(user_id or "")
    try:
        if ":" in raw:
            uid, version = raw.split(":", 1)
            user = db.session.get(User, int(uid))
            if user is None:
                return None
            if str(int(user.session_version or 0)) != str(version):
                return None
            return user
        return db.session.get(User, int(raw))
    except (TypeError, ValueError):
        return None


def validate_email_format(email: str) -> bool:
    email = (email or "").strip().lower()
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)) and len(email) <= 120


def staff_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.can_manage_users():
            if request.path.startswith("/api/"):
                return jsonify({"erro": "Apenas a equipe administrativa."}), 403
            flash("Apenas a equipe administrativa acessa esta área.", "error")
            return redirect(url_for("painel"))
        return view(*args, **kwargs)

    return wrapped


def last_vgs_owner(user) -> bool:
    if user.role != "vgs_owner":
        return False
    return User.query.filter_by(role="vgs_owner").count() <= 1


def manage_user_error(target, *, action: str):
    if getattr(target, "is_primary", False):
        if action in ("excluir", "cargo"):
            return "A conta padrão do site não pode ter o cargo alterado nem ser excluída."
        if action == "senha" and not current_user.is_vgs_owner:
            return "Só um VGS-Owner's pode redefinir a senha da conta padrão."
        if action == "senha":
            return None
    if target.id == current_user.id:
        if action == "excluir":
            return "Você não pode excluir a própria conta."
        if action == "cargo":
            return "Você não pode alterar o próprio cargo."
        return None
    if not config.can_manage_target(current_user.role, target.role):
        if current_user.role == "admin":
            return "Admin só pode gerenciar cargos abaixo de Admin."
        return "Você não pode gerenciar este usuário."
    return None


def slugify(value: str) -> str:
    text = (value or "").strip().lower()
    text = (
        text.replace("á", "a")
        .replace("à", "a")
        .replace("ã", "a")
        .replace("â", "a")
        .replace("é", "e")
        .replace("ê", "e")
        .replace("í", "i")
        .replace("ó", "o")
        .replace("ô", "o")
        .replace("õ", "o")
        .replace("ú", "u")
        .replace("ç", "c")
    )
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return (text or "aba")[:80]


def unique_slug(title: str, exclude_id=None) -> str:
    base = slugify(title)
    slug = base
    number = 2
    while True:
        query = Section.query.filter_by(slug=slug)
        if exclude_id:
            query = query.filter(Section.id != exclude_id)
        if not query.first():
            return slug
        slug = f"{base[:70]}-{number}"
        number += 1


def clean_https_url(value: str):
    url = (value or "").strip()
    if not url:
        return ""
    if any(char in url for char in ("\r", "\n", "\t", " ")):
        return None
    if len(url) > 500:
        return None
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        return None
    if parsed.username or parsed.password:
        return None
    return url


def parse_sort(value, default=0) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if number < 0 or number > 9999:
        return default
    return number


def divider_section_map() -> dict:
    mapping = {}
    for link in DividerSection.query.all():
        mapping.setdefault(link.divider_id, []).append(link.section_id)
    return mapping


def user_can_see_section(section: Section) -> bool:
    if current_user.role in config.STAFF_ROLES:
        return True
    divider_ids = [
        link.divider_id
        for link in DividerSection.query.filter_by(section_id=section.id).all()
    ]
    if not divider_ids:
        return (
            RoleSection.query.filter_by(role=current_user.role, section_id=section.id).first()
            is not None
        )
    return (
        RoleDivider.query.filter(
            RoleDivider.role == current_user.role,
            RoleDivider.divider_id.in_(divider_ids),
        ).first()
        is not None
    )


def visible_sections():
    rows = Section.query.order_by(Section.sort_order.asc(), Section.title.asc()).all()
    if current_user.role in config.STAFF_ROLES:
        return rows
    return [row for row in rows if user_can_see_section(row)]


def visible_items(section: Section):
    if not user_can_see_section(section):
        return []
    return (
        LibraryItem.query.filter_by(section_id=section.id)
        .order_by(LibraryItem.sort_order.asc(), LibraryItem.id.asc())
        .all()
    )


@app.context_processor
def inject_globals():
    assignable = []
    if getattr(current_user, "is_authenticated", False):
        assignable = config.assignable_roles(current_user.role)
    return {
        "ROLES": config.ROLES,
        "ROLE_LABELS": config.ROLE_LABELS,
        "ASSIGNABLE_ROLES": assignable,
        "TIER_LABELS": config.TIER_LABELS,
        "TIERS": config.TIERS,
        "KIND_LABELS": config.KIND_LABELS,
        "csrf_token": generate_csrf,
    }


@app.after_request
def set_security_headers(response):
    response = add_security_headers(response)
    token = getattr(g, "machine_token", "")
    if token:
        response = attach_machine_cookie(response, token)
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=120, stale-while-revalidate=86400"
    return response


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("painel"))
    return redirect(url_for("login"))


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("painel"))

    if request.method == "POST":
        if too_many_requests("login", 8, 15 * 60):
            flash("Muitas tentativas. Aguarde alguns minutos e tente de novo.", "error")
            return render_template("login.html")

        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(
            (func.lower(User.username) == identifier.lower())
            | (func.lower(User.email) == identifier.lower())
        ).first()

        if not user:
            flash(LOGIN_ERROR, "error")
            return render_template("login.html")

        if user.must_reset_password or not user.password_hash:
            start_password_reset(user.id)
            return render_template("set_password.html", user=user, forced=True)

        if not password or not user.check_password(password):
            flash(LOGIN_ERROR, "error")
            return render_template("login.html")

        login_user(user)
        return redirect(url_for("painel"))

    return render_template("login.html")


@app.before_request
def guard_manual_block():
    if request.endpoint in (None, "static", "favicon"):
        return
    block = manual_block_for_request()
    if block:
        serial = machine_serial_for_page()
        absorb_blocked_identity(block, serial)
        return render_template(
            "bloqueio_manual.html",
            serial=serial,
            blocked_ip=client_ip() or "",
        )


def manual_block_for_request():
    from datetime import datetime

    ips = {ip for ip in request_ips() if ip}
    cookie = (request.cookies.get(COOKIE_NAME) or "").strip().lower()
    if not ips and not cookie:
        return None
    now = datetime.utcnow()
    rows = (
        DeviceBlock.query.filter(
            DeviceBlock.manual.is_(True),
            DeviceBlock.blocked_until.isnot(None),
            DeviceBlock.blocked_until > now,
        )
        .order_by(DeviceBlock.id.desc())
        .all()
    )
    for row in rows:
        cookie_hit = bool(cookie and cookie == (row.token or "").lower())
        ip_hit = normalize_ip(row.ip) in ips
        if row.match_both:
            if cookie_hit or ip_hit:
                return row
            continue
        if row.match_serial:
            if cookie_hit:
                return row
            continue
        if ip_hit:
            return row
    return None


def machine_serial_for_page() -> str:
    cookie = (request.cookies.get(COOKIE_NAME) or "").strip().lower()
    if cookie:
        return cookie
    device = ensure_machine()
    g.machine_token = device.token
    return device.token or ""


def absorb_blocked_identity(row: DeviceBlock, serial: str) -> None:
    from datetime import datetime
    from secrets import token_hex

    serial = (serial or "").strip().lower()
    ip = client_ip()
    stored_serial = (row.token or "").lower()
    same_serial = bool(serial and serial == stored_serial)
    same_ip = bool(ip and normalize_ip(row.ip) == ip)
    changed = False
    if same_serial and (row.match_serial or row.match_both) and ip and not same_ip:
        row.ip = ip
        changed = True
    if same_ip and serial and not same_serial and not row.match_serial:
        other = DeviceBlock.query.filter_by(token=serial).first()
        if other and other.id != row.id:
            if other.manual and other.is_blocked():
                return
            other.token = token_hex(24)
            db.session.flush()
        row.token = serial
        changed = True
    if not changed:
        return
    row.attempt_count = (row.attempt_count or 0) + 1
    row.match_serial = False
    row.match_both = True
    row.updated_at = datetime.utcnow()
    db.session.commit()


@app.before_request
def remember_user_device():
    if request.endpoint in (None, "static", "favicon"):
        return
    if not getattr(current_user, "is_authenticated", False):
        return
    device = ensure_machine()
    g.machine_token = device.token
    ip = client_ip()
    changed = False
    if ip and current_user.last_ip != ip:
        current_user.last_ip = ip
        changed = True
    if device.token and current_user.machine_serial != device.token:
        current_user.machine_serial = device.token
        changed = True
    if changed:
        db.session.commit()


@app.before_request
def force_password_reset():
    if request.endpoint in (None, "static", "set_password", "logout", "login", "register", "favicon"):
        return
    if current_user.is_authenticated and getattr(current_user, "must_reset_password", False):
        return redirect(url_for("set_password"))


def blocked_response(device):
    ctx = blocked_page_context(device)
    return with_device_cookie(render_template("bloqueio.html", **ctx), device)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("painel"))

    device = identify_device(persist=False)
    refresh_block_state(device)
    if device.is_blocked():
        return blocked_response(device)

    if request.method == "POST":
        if too_many_requests("register", 8, 15 * 60):
            flash("Muitas tentativas. Aguarde alguns minutos e tente de novo.", "error")
            return with_device_cookie(render_template("register.html"), device)

        device = identify_device(persist=True)
        device = register_attempt(device)
        if device.is_blocked():
            return blocked_response(device)

        username = request.form.get("username", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:120]
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(username) < 3:
            flash("O nome de usuário deve ter pelo menos 3 caracteres.", "error")
        elif not config.is_gmail(email) or not validate_email_format(email):
            flash("O cadastro público aceita apenas e-mail @gmail.com.", "error")
        elif len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "error")
        elif password != confirm:
            flash("As senhas não coincidem.", "error")
        elif User.query.filter_by(username=username).first():
            flash("Este nome de usuário já está em uso.", "error")
        elif User.query.filter(func.lower(User.email) == email).first():
            flash("Este e-mail já está cadastrado.", "error")
        else:
            try:
                exists, detail = verify_mailbox(email)
            except Exception:
                exists, detail = True, ""
            if not exists:
                flash(detail or "Este e-mail não existe.", "error")
            else:
                user = User(username=username, email=email, role="visitante")
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash("Conta básica criada. Entre para continuar.", "success")
                return with_device_cookie(redirect(url_for("login")), device)

    return with_device_cookie(render_template("register.html"), device)


@app.route("/set-password", methods=["GET", "POST"])
def set_password():
    def resolve_reset_user():
        if current_user.is_authenticated and getattr(current_user, "must_reset_password", False):
            return current_user
        uid = pending_reset_user_id()
        if not uid:
            return None
        user = db.session.get(User, uid)
        if not user or not (user.must_reset_password or not user.password_hash):
            return None
        return user

    user = resolve_reset_user()
    if request.method == "POST":
        if too_many_requests("set-password", 8, 15 * 60):
            flash("Muitas tentativas. Aguarde alguns minutos e tente de novo.", "error")
            return redirect(url_for("login"))
        if not user:
            flash("Esta conta não está aguardando redefinição de senha.", "error")
            return redirect(url_for("login"))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 6:
            flash("A senha deve ter pelo menos 6 caracteres.", "error")
            return render_template("set_password.html", user=user, forced=True)
        if password != confirm:
            flash("As senhas não coincidem.", "error")
            return render_template("set_password.html", user=user, forced=True)
        user.set_password(password)
        db.session.commit()
        clear_password_reset()
        login_user(user)
        flash("Senha definida com sucesso.", "success")
        return redirect(url_for("painel"))

    if user:
        return render_template("set_password.html", user=user, forced=True)
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Você saiu do sistema.", "info")
    return redirect(url_for("login"))


@app.route("/painel")
@login_required
def painel():
    return render_template(
        "painel.html",
        can_edit=current_user.can_edit_library(),
        is_admin=current_user.can_manage_users(),
        is_vgs_owner=current_user.is_vgs_owner,
        user_id=current_user.id,
        username=current_user.username,
        seen_ip=client_ip(),
        allowed_tiers=sorted(config.tiers_for(current_user.role)),
    )


def item_payload(item: LibraryItem) -> dict:
    data = item.to_dict()
    locked = not config.can_see_tier(current_user.role, data["tier"])
    data["locked"] = locked
    if locked:
        data["url"] = ""
        data["body"] = ""
    return data


def section_payload(section: Section, *, include_hidden=False) -> dict:
    if include_hidden:
        count = LibraryItem.query.filter_by(section_id=section.id).count()
    else:
        count = len(visible_items(section))
    return section.to_dict(item_count=count)


@app.route("/api/secoes")
@login_required
def api_list_sections():
    staff = current_user.can_edit_library()
    rows = (
        Section.query.order_by(Section.sort_order.asc(), Section.title.asc()).all()
        if staff
        else visible_sections()
    )
    dividers = NavDivider.query.order_by(NavDivider.sort_order.asc(), NavDivider.id.asc()).all()
    links = divider_section_map()
    visible_ids = {row.id for row in rows}
    if not staff and links:
        allowed = {
            grant.divider_id
            for grant in RoleDivider.query.filter_by(role=current_user.role).all()
        }
        dividers = [row for row in dividers if row.id in allowed]
    return jsonify({
        "secoes": [section_payload(row, include_hidden=staff) for row in rows],
        "divisoes": [
            {
                **row.to_dict(),
                "section_ids": [section_id for section_id in links.get(row.id, []) if section_id in visible_ids],
            }
            for row in dividers
        ],
    })


@app.route("/api/divisoes", methods=["POST"])
@staff_required
def api_create_divider():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:40]
    if len(title) < 2:
        return jsonify({"erro": "Informe o nome da divisão."}), 400
    row = NavDivider(title=title, sort_order=parse_sort(data.get("sort_order"), 0))
    db.session.add(row)
    db.session.commit()
    return jsonify({"divisao": row.to_dict()}), 201


@app.route("/api/divisoes/<int:divider_id>", methods=["PUT"])
@staff_required
def api_update_divider(divider_id):
    row = db.session.get(NavDivider, divider_id)
    if not row:
        return jsonify({"erro": "Divisão não encontrada."}), 404
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:40]
    if len(title) < 2:
        return jsonify({"erro": "Informe o nome da divisão."}), 400
    row.title = title
    row.sort_order = parse_sort(data.get("sort_order"), row.sort_order)
    db.session.commit()
    return jsonify({"divisao": row.to_dict()})


@app.route("/api/divisoes/<int:divider_id>", methods=["DELETE"])
@staff_required
def api_delete_divider(divider_id):
    row = db.session.get(NavDivider, divider_id)
    if not row:
        return jsonify({"erro": "Divisão não encontrada."}), 404
    DividerSection.query.filter_by(divider_id=row.id).delete(synchronize_session=False)
    RoleDivider.query.filter_by(divider_id=row.id).delete(synchronize_session=False)
    db.session.delete(row)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/secoes", methods=["POST"])
@staff_required
def api_create_section():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:80]
    description = (data.get("description") or "").strip()[:400]
    icon = (data.get("icon") or "💾").strip()[:8] or "💾"
    tier = (data.get("tier") or "basico").strip()
    if len(title) < 2:
        return jsonify({"erro": "Informe o nome da aba."}), 400
    if tier not in config.TIERS:
        return jsonify({"erro": "Selecione o acesso da aba."}), 400
    section = Section(
        slug=unique_slug(title),
        title=title,
        description=description,
        icon=icon,
        tier=tier,
        sort_order=parse_sort(data.get("sort_order"), 0),
    )
    db.session.add(section)
    db.session.commit()
    return jsonify({"secao": section_payload(section, include_hidden=True)}), 201


@app.route("/api/secoes/<int:section_id>", methods=["PUT"])
@staff_required
def api_update_section(section_id):
    section = db.session.get(Section, section_id)
    if not section:
        return jsonify({"erro": "Aba não encontrada."}), 404
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:80]
    description = (data.get("description") or "").strip()[:400]
    icon = (data.get("icon") or "💾").strip()[:8] or "💾"
    tier = (data.get("tier") or "").strip()
    if len(title) < 2:
        return jsonify({"erro": "Informe o nome da aba."}), 400
    if tier not in config.TIERS:
        return jsonify({"erro": "Selecione o acesso da aba."}), 400
    section.title = title
    section.description = description
    section.icon = icon
    section.tier = tier
    section.sort_order = parse_sort(data.get("sort_order"), section.sort_order or 0)
    if title and section.slug != slugify(title):
        section.slug = unique_slug(title, exclude_id=section.id)
    db.session.commit()
    return jsonify({"secao": section_payload(section, include_hidden=True)})


@app.route("/api/secoes/<int:section_id>", methods=["DELETE"])
@staff_required
def api_delete_section(section_id):
    section = db.session.get(Section, section_id)
    if not section:
        return jsonify({"erro": "Aba não encontrada."}), 404
    RoleSection.query.filter_by(section_id=section.id).delete(synchronize_session=False)
    DividerSection.query.filter_by(section_id=section.id).delete(synchronize_session=False)
    db.session.delete(section)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/secoes/<int:section_id>/itens")
@login_required
def api_list_items(section_id):
    section = db.session.get(Section, section_id)
    if not section:
        return jsonify({"erro": "Aba não encontrada."}), 404
    staff = current_user.can_edit_library()
    if not staff and not user_can_see_section(section):
        return jsonify({"erro": "Aba indisponível para o seu cargo."}), 403
    if staff:
        items = (
            LibraryItem.query.filter_by(section_id=section.id)
            .order_by(LibraryItem.sort_order.asc(), LibraryItem.id.asc())
            .all()
        )
    else:
        items = visible_items(section)
    return jsonify({
        "secao": section_payload(section, include_hidden=staff),
        "itens": [item_payload(item) for item in items],
    })


def normalize_item(data: dict, section: Section):
    title = (data.get("title") or "").strip()[:120]
    description = (data.get("description") or "").strip()[:400]
    body = (data.get("body") or "").strip()[:4000]
    kind = (data.get("kind") or "download").strip()
    tier = (data.get("tier") or "").strip()
    url = clean_https_url(data.get("url") or "")
    if len(title) < 2:
        return None, "Informe o nome do botão."
    if kind not in config.ITEM_KINDS:
        return None, "Selecione se é download ou tutorial."
    if url is None:
        return None, "O link precisa ser um endereço https, sem espaços."
    if tier and tier not in config.TIERS:
        return None, "Selecione o acesso do botão."
    if kind == "download" and not url:
        return None, "Cole o link do MediaFire."
    if kind == "tutorial" and not url and not body:
        return None, "Um tutorial precisa de texto ou de um link."
    return {
        "title": title,
        "description": description,
        "body": body if kind == "tutorial" else "",
        "url": url,
        "kind": kind,
        "tier": tier or None,
        "sort_order": parse_sort(data.get("sort_order"), 0),
        "section": section,
    }, None


@app.route("/api/itens", methods=["POST"])
@staff_required
def api_create_item():
    data = request.get_json(silent=True) or {}
    section = db.session.get(Section, data.get("section_id"))
    if not section:
        return jsonify({"erro": "Selecione a aba."}), 400
    payload, error = normalize_item(data, section)
    if error:
        return jsonify({"erro": error}), 400
    item = LibraryItem(
        section_id=section.id,
        title=payload["title"],
        description=payload["description"],
        body=payload["body"],
        url=payload["url"],
        kind=payload["kind"],
        tier=payload["tier"],
        sort_order=payload["sort_order"],
    )
    db.session.add(item)
    db.session.commit()
    return jsonify({"item": item.to_dict()}), 201


@app.route("/api/itens/<int:item_id>", methods=["PUT"])
@staff_required
def api_update_item(item_id):
    item = db.session.get(LibraryItem, item_id)
    if not item:
        return jsonify({"erro": "Botão não encontrado."}), 404
    data = request.get_json(silent=True) or {}
    section = db.session.get(Section, data.get("section_id") or item.section_id)
    if not section:
        return jsonify({"erro": "Selecione a aba."}), 400
    payload, error = normalize_item(data, section)
    if error:
        return jsonify({"erro": error}), 400
    item.section_id = section.id
    item.title = payload["title"]
    item.description = payload["description"]
    item.body = payload["body"]
    item.url = payload["url"]
    item.kind = payload["kind"]
    item.tier = payload["tier"]
    item.sort_order = payload["sort_order"]
    db.session.commit()
    return jsonify({"item": item.to_dict()})


@app.route("/api/itens/<int:item_id>", methods=["DELETE"])
@staff_required
def api_delete_item(item_id):
    item = db.session.get(LibraryItem, item_id)
    if not item:
        return jsonify({"erro": "Botão não encontrado."}), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/usuarios")
@staff_required
def api_list_users():
    users = User.query.order_by(User.created_at.asc()).all()
    assignable = config.assignable_roles(current_user.role)
    return jsonify({
        "assignable_roles": assignable,
        "usuarios": [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_self": user.id == current_user.id,
                "is_primary": bool(user.is_primary),
                "must_reset_password": bool(user.must_reset_password),
                "last_ip": user.last_ip or "",
                "machine_serial": user.machine_serial or "",
                "can_edit_role": (
                    not user.is_primary
                    and user.id != current_user.id
                    and config.can_manage_target(current_user.role, user.role)
                ),
                "can_manage": (
                    not user.is_primary
                    and user.id != current_user.id
                    and config.can_manage_target(current_user.role, user.role)
                ),
                "can_reset": (
                    (bool(user.is_primary) and current_user.is_vgs_owner)
                    or (
                        not user.is_primary
                        and (
                            user.id == current_user.id
                            or config.can_manage_target(current_user.role, user.role)
                        )
                    )
                ),
            }
            for user in users
        ],
    })


@app.route("/api/usuarios", methods=["POST"])
@staff_required
def api_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()[:80]
    email = (data.get("email") or "").strip().lower()[:120]
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""
    role = (data.get("role") or "visitante").strip()

    if len(username) < 3:
        return jsonify({"erro": "O nome de usuário deve ter pelo menos 3 caracteres."}), 400
    if not validate_email_format(email):
        return jsonify({"erro": "Informe um e-mail válido."}), 400
    if len(password) < 6:
        return jsonify({"erro": "A senha deve ter pelo menos 6 caracteres."}), 400
    if password != confirm:
        return jsonify({"erro": "As senhas não coincidem."}), 400
    if role not in config.assignable_roles(current_user.role):
        return jsonify({"erro": "Você não pode atribuir este cargo."}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"erro": "Este nome de usuário já está em uso."}), 400
    if User.query.filter(func.lower(User.email) == email).first():
        return jsonify({"erro": "Este e-mail já está cadastrado."}), 400

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"erro": "Este usuário ou e-mail já está cadastrado."}), 400
    return jsonify({
        "ok": True,
        "usuario": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }), 201


@app.route("/api/usuarios/<int:user_id>/cargo", methods=["POST"])
@staff_required
def api_update_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    blocked = manage_user_error(user, action="cargo")
    if blocked:
        return jsonify({"erro": blocked}), 400
    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip()
    if role not in config.assignable_roles(current_user.role):
        return jsonify({"erro": "Você não pode atribuir este cargo."}), 400
    if last_vgs_owner(user) and role != "vgs_owner":
        return jsonify({"erro": "Não é possível remover o último VGS-Owner's."}), 400
    user.role = role
    db.session.commit()
    return jsonify({"ok": True, "role": user.role})


@app.route("/api/usuarios/<int:user_id>/redefinir-senha", methods=["POST"])
@staff_required
def api_reset_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    blocked = manage_user_error(user, action="senha")
    if blocked:
        return jsonify({"erro": blocked}), 400
    user.must_reset_password = True
    user.bump_session()
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/usuarios/<int:user_id>", methods=["DELETE"])
@staff_required
def api_delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"erro": "Usuário não encontrado."}), 404
    blocked = manage_user_error(user, action="excluir")
    if blocked:
        return jsonify({"erro": blocked}), 400
    if last_vgs_owner(user):
        return jsonify({"erro": "Não é possível excluir o último VGS-Owner's."}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/acessos")
@staff_required
def api_list_access():
    dividers = NavDivider.query.order_by(NavDivider.sort_order.asc(), NavDivider.id.asc()).all()
    grants = RoleDivider.query.all()
    by_role = {}
    for grant in grants:
        by_role.setdefault(grant.role, []).append(grant.divider_id)
    return jsonify({
        "divisoes": [
            {"id": row.id, "title": row.title}
            for row in dividers
        ],
        "cargos": [
            {
                "role": role,
                "label": config.role_label(role),
                "divider_ids": by_role.get(role, []),
            }
            for role in config.CONFIGURABLE_ROLES
        ],
    })


@app.route("/api/acessos", methods=["PUT"])
@staff_required
def api_save_access():
    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip()
    if role not in config.CONFIGURABLE_ROLES:
        return jsonify({"erro": "Este cargo não entra na seleção de divisões."}), 400
    raw_ids = data.get("divider_ids") or []
    wanted = set()
    for value in raw_ids:
        try:
            wanted.add(int(value))
        except (TypeError, ValueError):
            continue
    valid = {
        divider_id
        for (divider_id,) in db.session.query(NavDivider.id).filter(NavDivider.id.in_(wanted or {0})).all()
    } if wanted else set()
    RoleDivider.query.filter_by(role=role).delete(synchronize_session=False)
    for divider_id in sorted(valid):
        db.session.add(RoleDivider(role=role, divider_id=divider_id))
    db.session.commit()
    return jsonify({"ok": True, "role": role, "divider_ids": sorted(valid)})


@app.route("/api/canais-divisao")
@staff_required
def api_list_divider_channels():
    dividers = NavDivider.query.order_by(NavDivider.sort_order.asc(), NavDivider.id.asc()).all()
    sections = Section.query.order_by(Section.sort_order.asc(), Section.title.asc()).all()
    links = divider_section_map()
    return jsonify({
        "divisoes": [
            {"id": row.id, "title": row.title, "section_ids": links.get(row.id, [])}
            for row in dividers
        ],
        "secoes": [
            {"id": row.id, "title": row.title, "icon": row.icon or "💾"}
            for row in sections
        ],
    })


@app.route("/api/canais-divisao", methods=["PUT"])
@staff_required
def api_save_divider_channels():
    data = request.get_json(silent=True) or {}
    try:
        divider_id = int(data.get("divider_id"))
    except (TypeError, ValueError):
        return jsonify({"erro": "Selecione a divisão."}), 400
    divider = db.session.get(NavDivider, divider_id)
    if not divider:
        return jsonify({"erro": "Divisão não encontrada."}), 404
    raw_ids = data.get("section_ids") or []
    wanted = set()
    for value in raw_ids:
        try:
            wanted.add(int(value))
        except (TypeError, ValueError):
            continue
    valid = {
        section_id
        for (section_id,) in db.session.query(Section.id).filter(Section.id.in_(wanted or {0})).all()
    } if wanted else set()
    DividerSection.query.filter_by(divider_id=divider.id).delete(synchronize_session=False)
    for section_id in sorted(valid):
        db.session.add(DividerSection(divider_id=divider.id, section_id=section_id))
    db.session.commit()
    return jsonify({"ok": True, "divider_id": divider.id, "section_ids": sorted(valid)})


def clean_block_ip(value: str):
    return normalize_ip(value) or None


def clean_serial(value: str):
    text = (value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{16,64}", text):
        return None
    return text


def block_until_from(data: dict):
    from datetime import datetime

    if bool(data.get("permanent")):
        return datetime(2099, 1, 1), None
    delta = parse_block_duration(data.get("amount"), data.get("unit"))
    if not delta:
        return None, "Informe o tempo do bloqueio ou marque permanente."
    return datetime.utcnow() + delta, None


@app.route("/api/meu-ip")
@staff_required
def api_seen_ip():
    ips = request_ips()
    return jsonify({"ip": ips[0] if ips else "", "ips": ips})


@app.route("/api/bloqueios", methods=["POST"])
@staff_required
def api_create_block():
    from datetime import datetime

    data = request.get_json(silent=True) or {}
    until, error = block_until_from(data)
    if error:
        return jsonify({"erro": error}), 400
    mode = (data.get("mode") or "ip").strip()
    if mode == "serial":
        serial = clean_serial(data.get("serial") or "")
        if not serial:
            return jsonify({"erro": "Informe o serial do navegador."}), 400
        row = DeviceBlock.query.filter_by(token=serial).first()
        if row is None:
            return jsonify({"erro": "Esse serial ainda não apareceu. A pessoa precisa abrir o site nesse navegador."}), 400
        row.manual = True
        row.match_serial = True
        row.match_both = False
        row.blocked_until = until
        row.updated_at = datetime.utcnow()
    elif mode == "ambos":
        account = (data.get("account") or "").strip().lower()
        if not account:
            return jsonify({"erro": "Informe o usuário ou o e-mail."}), 400
        person = User.query.filter(
            (func.lower(User.username) == account) | (func.lower(User.email) == account)
        ).first()
        if person is None:
            return jsonify({"erro": "Usuário ou e-mail não encontrado."}), 400
        ip = clean_block_ip(person.last_ip or "")
        serial = clean_serial(person.machine_serial or "")
        if not ip or not serial:
            return jsonify({"erro": "Essa conta ainda não tem IP e serial. A pessoa precisa abrir o site nesse navegador."}), 400
        row = DeviceBlock.query.filter_by(token=serial).first()
        if row is None:
            return jsonify({"erro": "Esse serial ainda não apareceu. A pessoa precisa abrir o site nesse navegador."}), 400
        row.ip = ip
        row.manual = True
        row.match_serial = False
        row.match_both = True
        row.blocked_until = until
        row.updated_at = datetime.utcnow()
    else:
        ip = clean_block_ip(data.get("ip") or "")
        if not ip:
            return jsonify({"erro": "Informe o IP da máquina."}), 400
        row = DeviceBlock(
            token=os.urandom(24).hex(),
            ip=ip,
            manual=True,
            match_serial=False,
            match_both=False,
            attempt_count=0,
            strike_level=0,
            blocked_until=until,
        )
        db.session.add(row)
    db.session.commit()
    return jsonify({"ok": True, "bloqueio": row.to_dict()}), 201


@app.route("/api/bloqueios")
@staff_required
def api_list_blocks():
    from datetime import datetime

    now = datetime.utcnow()
    rows = (
        DeviceBlock.query.filter(DeviceBlock.blocked_until.isnot(None))
        .filter(DeviceBlock.blocked_until > now)
        .order_by(DeviceBlock.blocked_until.desc())
        .all()
    )
    return jsonify({"bloqueios": [row.to_dict() for row in rows]})


@app.route("/api/bloqueios/<int:block_id>/tempo", methods=["POST"])
@staff_required
def api_set_block_duration(block_id):
    from datetime import datetime

    row = db.session.get(DeviceBlock, block_id)
    if not row:
        return jsonify({"erro": "Bloqueio não encontrado."}), 404
    data = request.get_json(silent=True) or {}
    delta = parse_block_duration(data.get("amount"), data.get("unit"))
    if not delta:
        return jsonify({"erro": "Informe um número válido e a unidade de tempo."}), 400
    row.blocked_until = datetime.utcnow() + delta
    row.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "bloqueio": row.to_dict()})


@app.route("/api/bloqueios/<int:block_id>", methods=["DELETE"])
@staff_required
def api_remove_block(block_id):
    from datetime import datetime

    row = db.session.get(DeviceBlock, block_id)
    if not row:
        return jsonify({"erro": "Bloqueio não encontrado."}), 404
    row.blocked_until = None
    row.attempt_count = 0
    row.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes"),
        host="127.0.0.1",
        port=5000,
        threaded=True,
    )
