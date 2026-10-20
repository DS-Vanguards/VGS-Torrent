import os
import re
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, flash, jsonify, redirect, render_template, request, send_from_directory, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from sqlalchemy import event, func
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

import config
from core.layout_sig import bind as _layout_bind
from device_guard import (
    blocked_page_context,
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
    pending_reset_user_id,
    start_password_reset,
    too_many_requests,
)
from models import DeviceBlock, LibraryItem, Section, User, ensure_schema, init_default_data

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


def _should_migrate_schema() -> bool:
    if os.environ.get("RUN_DB_MIGRATE", "").lower() in ("1", "true", "yes"):
        return True
    return not os.environ.get("VERCEL")


with app.app_context():
    if _should_migrate_schema():
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


def visible_sections():
    allowed = config.tiers_for(current_user.role)
    rows = Section.query.order_by(Section.sort_order.asc(), Section.title.asc()).all()
    return [row for row in rows if row.tier in allowed]


def visible_items(section: Section):
    allowed = config.tiers_for(current_user.role)
    if section.tier not in allowed:
        return []
    items = (
        LibraryItem.query.filter_by(section_id=section.id)
        .order_by(LibraryItem.sort_order.asc(), LibraryItem.id.asc())
        .all()
    )
    return [item for item in items if item.effective_tier() in allowed]


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
            (User.username == identifier) | (func.lower(User.email) == identifier.lower())
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
                flash("Conta de visitante criada. Entre para continuar.", "success")
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
    )


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
    return jsonify({"secoes": [section_payload(row, include_hidden=staff) for row in rows]})


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
    if not staff and section.tier not in config.tiers_for(current_user.role):
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
        "itens": [item.to_dict() for item in items],
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
                "must_reset_password": bool(user.must_reset_password),
                "can_edit_role": (
                    user.id != current_user.id
                    and config.can_manage_target(current_user.role, user.role)
                ),
                "can_manage": (
                    user.id != current_user.id
                    and config.can_manage_target(current_user.role, user.role)
                ),
                "can_reset": (
                    user.id == current_user.id
                    or config.can_manage_target(current_user.role, user.role)
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
