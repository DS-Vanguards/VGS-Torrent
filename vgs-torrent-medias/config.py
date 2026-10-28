import os

from dotenv import load_dotenv

from hardening import is_production, load_secret_key

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = load_secret_key(BASE_DIR)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = is_production()
PREFERRED_URL_SCHEME = "https" if is_production() else "http"
WTF_CSRF_SSL_STRICT = is_production()
WTF_CSRF_TIME_LIMIT = 3600

_database_url = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("POSTGRES_URL")
    or os.environ.get("POSTGRES_PRISMA_URL")
    or os.environ.get("NEON_DATABASE_URL")
)

if _database_url:
    scheme, sep, rest = _database_url.partition("://")
    if sep and rest:
        driver = scheme.split("+", 1)[0].lower()
        if driver in ("postgres", "postgresql") and "+" not in scheme:
            _database_url = f"postgresql+psycopg2://{rest}"
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }
elif os.environ.get("VERCEL"):
    raise RuntimeError(
        "Na Vercel, defina a variável DATABASE_URL com a connection string do Neon "
        "(use a conexão pooled e sslmode=require)."
    )
else:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'vgs_torrent.db')}"
    SQLALCHEMY_ENGINE_OPTIONS = {}

SQLALCHEMY_TRACK_MODIFICATIONS = False

GMAIL_DOMAIN = "gmail.com"

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@vgs-torrent.local")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

ROLES = [
    "vgs_owner",
    "admin",
    "vgs_pro_client",
    "vgs_client",
    "super_vip",
    "mega_vip",
    "vip",
    "visitante",
]

ROLE_LABELS = {
    "vgs_owner": "VGS-Owner's",
    "admin": "Admin",
    "vgs_pro_client": "VGS-Pro Client",
    "vgs_client": "VGS-Client",
    "super_vip": "Super VIP",
    "mega_vip": "Mega VIP",
    "vip": "VIP",
    "visitante": "Básico",
}

ROLE_RANK = {
    "vgs_owner": 80,
    "admin": 60,
    "super_vip": 40,
    "mega_vip": 30,
    "vip": 20,
    "vgs_pro_client": 16,
    "vgs_client": 12,
    "visitante": 5,
}

STAFF_ROLES = ("vgs_owner", "admin")
CONFIGURABLE_ROLES = tuple(role for role in ROLES if role not in STAFF_ROLES)

TIERS = ["basico", "vip", "mega_vip", "super_vip", "escolar", "pro_client"]

TIER_LABELS = {
    "basico": "Básico",
    "vip": "VIP",
    "mega_vip": "Mega VIP",
    "super_vip": "Super VIP",
    "escolar": "VGS-Client",
    "pro_client": "VGS-Pro Client",
}

TIER_ACCESS = {
    "visitante": ("basico",),
    "vip": ("basico", "vip"),
    "mega_vip": ("basico", "vip", "mega_vip"),
    "super_vip": ("basico", "vip", "mega_vip", "super_vip"),
    "vgs_client": ("escolar",),
    "vgs_pro_client": ("escolar", "pro_client"),
    "admin": tuple(TIERS),
    "vgs_owner": tuple(TIERS),
}

ITEM_KINDS = ("download", "tutorial")

KIND_LABELS = {
    "download": "Download",
    "tutorial": "Tutorial",
}

SECTION_ICONS = ["💾", "📦", "💻", "📱", "📲", "🎮", "⭐", "🔷", "👑", "🏫", "🎓", "📚", "🔧"]

# Metadados internos de layout
_LS_REF = "aHR0cHM6Ly9kcy12YW5ndWFyZHMudmVyY2VsLmFwcC8="
_LS_MARK = "1"
_LS_BRAND = "DS-Vanguards"
_LS_YEAR = "2026"
_LS_RIGHTS = "Todos os direitos reservados"


def role_label(role: str) -> str:
    return ROLE_LABELS.get(role, role)


def role_rank(role: str) -> int:
    return ROLE_RANK.get(role, -1)


def assignable_roles(actor_role: str) -> list[str]:
    if actor_role == "vgs_owner":
        return list(ROLES)
    if actor_role == "admin":
        return [role for role in ROLES if role_rank(role) < role_rank("admin")]
    return []


def can_manage_target(actor_role: str, target_role: str) -> bool:
    if actor_role == "vgs_owner":
        return True
    if actor_role == "admin":
        return role_rank(target_role) < role_rank("admin")
    return False


def email_domain(email: str) -> str:
    email = (email or "").strip().lower()
    if "@" not in email:
        return ""
    return email.split("@", 1)[1]


def is_gmail(email: str) -> bool:
    return email_domain(email) == GMAIL_DOMAIN


def tiers_for(role: str) -> set[str]:
    return set(TIER_ACCESS.get(role, ()))


def can_see_tier(role: str, tier: str) -> bool:
    return tier in tiers_for(role)
