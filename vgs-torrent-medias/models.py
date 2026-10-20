from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

import config
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default="visitante", nullable=False)
    must_reset_password = db.Column(db.Boolean, default=False, nullable=False)
    session_version = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return f"{self.id}:{int(self.session_version or 0)}"

    def bump_session(self) -> None:
        self.session_version = int(self.session_version or 0) + 1

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)
        self.must_reset_password = False
        self.bump_session()

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_vgs_owner(self) -> bool:
        return self.role == "vgs_owner"

    @property
    def role_label(self) -> str:
        return config.role_label(self.role)

    def can_edit_library(self) -> bool:
        return self.role in config.STAFF_ROLES

    def can_manage_users(self) -> bool:
        return self.role in config.STAFF_ROLES

    def can_see_tier(self, tier: str) -> bool:
        return config.can_see_tier(self.role, tier)


class DeviceBlock(db.Model):
    __tablename__ = "device_blocks"

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip = db.Column(db.String(64), default="", nullable=False, index=True)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    strike_level = db.Column(db.Integer, default=0, nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def is_blocked(self) -> bool:
        return bool(self.blocked_until and self.blocked_until > datetime.utcnow())

    def to_dict(self) -> dict:
        until = self.blocked_until
        return {
            "id": self.id,
            "token": self.token[:12],
            "ip": self.ip or "—",
            "attempt_count": self.attempt_count,
            "strike_level": self.strike_level,
            "blocked_until": until.strftime("%d/%m/%Y %H:%M") if until else "",
            "level_label": "1 dia" if self.strike_level >= 6 else "5 min",
        }


class Section(db.Model):
    __tablename__ = "sections"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    title = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(400), default="", nullable=False)
    icon = db.Column(db.String(8), default="💾", nullable=False)
    tier = db.Column(db.String(32), default="basico", nullable=False)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = db.relationship(
        "LibraryItem",
        backref="section",
        cascade="all, delete-orphan",
        order_by="LibraryItem.sort_order",
    )

    def to_dict(self, *, item_count=0) -> dict:
        return {
            "id": self.id,
            "slug": self.slug,
            "title": self.title,
            "description": self.description or "",
            "icon": self.icon or "💾",
            "tier": self.tier,
            "tier_label": config.TIER_LABELS.get(self.tier, self.tier),
            "sort_order": self.sort_order,
            "item_count": item_count,
        }


class LibraryItem(db.Model):
    __tablename__ = "library_items"

    id = db.Column(db.Integer, primary_key=True)
    section_id = db.Column(
        db.Integer,
        db.ForeignKey("sections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(400), default="", nullable=False)
    body = db.Column(db.Text, default="", nullable=False)
    url = db.Column(db.String(500), default="", nullable=False)
    kind = db.Column(db.String(20), default="download", nullable=False)
    tier = db.Column(db.String(32), nullable=True)
    sort_order = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def effective_tier(self) -> str:
        if self.tier:
            return self.tier
        if self.section is not None:
            return self.section.tier
        return "basico"

    def to_dict(self) -> dict:
        tier = self.effective_tier()
        return {
            "id": self.id,
            "section_id": self.section_id,
            "title": self.title,
            "description": self.description or "",
            "body": self.body or "",
            "url": self.url or "",
            "kind": self.kind,
            "kind_label": config.KIND_LABELS.get(self.kind, self.kind),
            "tier": tier,
            "tier_override": self.tier or "",
            "tier_label": config.TIER_LABELS.get(tier, tier),
            "sort_order": self.sort_order,
        }


def ensure_schema() -> None:
    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("users")}
    if "must_reset_password" not in columns:
        db.session.execute(
            text("ALTER TABLE users ADD COLUMN must_reset_password BOOLEAN NOT NULL DEFAULT FALSE")
        )
        db.session.commit()
    if "session_version" not in columns:
        db.session.execute(
            text("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
        )
        db.session.commit()


def init_default_data() -> None:
    try:
        bootstrap = User.query.filter(
            (User.username == config.ADMIN_USERNAME) | (User.email == config.ADMIN_EMAIL)
        ).first()
        has_owner = User.query.filter_by(role="vgs_owner").first() is not None
        if not has_owner:
            if bootstrap:
                bootstrap.role = "vgs_owner"
                db.session.commit()
            elif config.ADMIN_PASSWORD:
                owner = User(
                    username=config.ADMIN_USERNAME,
                    email=config.ADMIN_EMAIL,
                    role="vgs_owner",
                )
                owner.set_password(config.ADMIN_PASSWORD)
                db.session.add(owner)
                db.session.commit()
        if Section.query.first() is None:
            for slug, title, icon, tier, description, order in _STARTER_SECTIONS:
                db.session.add(
                    Section(
                        slug=slug,
                        title=title,
                        icon=icon,
                        tier=tier,
                        description=description,
                        sort_order=order,
                    )
                )
            db.session.commit()
    except IntegrityError:
        db.session.rollback()
    except Exception:
        db.session.rollback()


_STARTER_SECTIONS = (
    (
        "sistemas",
        "Sistemas",
        "💾",
        "basico",
        "Sistemas usados no dia a dia da Vanguards.",
        10,
    ),
    (
        "aplicativos",
        "Aplicativos",
        "📦",
        "basico",
        "Aplicativos e utilitários do dia a dia.",
        20,
    ),
    (
        "computadores",
        "Computadores",
        "💻",
        "basico",
        "Formatação e configuração de computadores.",
        30,
    ),
    (
        "tablets",
        "Tablets",
        "📱",
        "basico",
        "Formatação e configuração de tablets.",
        40,
    ),
    (
        "celulares",
        "Celulares",
        "📲",
        "basico",
        "Configuração de celulares.",
        50,
    ),
    (
        "videogames",
        "Videogames",
        "🎮",
        "basico",
        "Configuração de videogames.",
        60,
    ),
    (
        "desbloqueios",
        "Desbloqueios",
        "🔧",
        "basico",
        "Materiais de desbloqueio usados pela equipe. Os links entram pelo painel.",
        70,
    ),
    (
        "tutoriais-vip",
        "Tutoriais VIP",
        "⭐",
        "vip",
        "Tutoriais específicos do cargo VIP.",
        80,
    ),
    (
        "downloads-vip",
        "Downloads VIP",
        "⭐",
        "vip",
        "Downloads específicos do cargo VIP.",
        90,
    ),
    (
        "tutoriais-avancados",
        "Tutoriais avançados",
        "🔷",
        "mega_vip",
        "Tutoriais avançados do cargo Mega VIP.",
        100,
    ),
    (
        "downloads-avancados",
        "Downloads avançados",
        "🔷",
        "mega_vip",
        "Downloads avançados do cargo Mega VIP.",
        110,
    ),
    (
        "acervo-completo",
        "Acervo completo",
        "👑",
        "super_vip",
        "Tutoriais e downloads do acesso completo Super VIP.",
        120,
    ),
    (
        "ambiente-escolar",
        "Ambiente escolar",
        "🏫",
        "escolar",
        "Tutoriais e downloads exclusivos de ambiente escolar.",
        130,
    ),
    (
        "ambiente-escolar-pro",
        "Ambiente escolar Pro",
        "🎓",
        "pro_client",
        "Conteúdos do VGS-Pro Client, além do ambiente escolar.",
        140,
    ),
)
