import smtplib
import time
from email.utils import parseaddr

try:
    import dns.resolver as dns_resolver
except ImportError:  # pragma: no cover
    dns_resolver = None

GOOGLE_DOMAINS = {"gmail.com", "googlemail.com"}
SMTP_TIMEOUT = 3


def normalize_email(email: str) -> str:
    _, addr = parseaddr((email or "").strip().lower())
    return addr


def lookup_mx(domain: str) -> tuple[list[str], str]:
    if not domain or dns_resolver is None:
        return [], "unavailable"
    try:
        answers = dns_resolver.resolve(domain, "MX", lifetime=5)
        records = sorted(
            [(int(r.preference), str(r.exchange).rstrip(".").lower()) for r in answers],
            key=lambda item: item[0],
        )
        hosts = [host for _, host in records if host]
        if not hosts:
            return [], "missing"
        return hosts, "ok"
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer, dns_resolver.NoNameservers):
        return [], "missing"
    except Exception:
        return [], "timeout"


def _rcpt_status(mx_host: str, email: str) -> int | None:
    try:
        with smtplib.SMTP(timeout=SMTP_TIMEOUT) as smtp:
            smtp.connect(mx_host, 25)
            smtp.helo("vgs-torrent.local")
            smtp.mail("noreply@vgs-torrent.local")
            code, _ = smtp.rcpt(email)
            try:
                smtp.rset()
            except Exception:
                pass
            return int(code)
    except Exception:
        return None


def verify_mailbox(email: str) -> tuple[bool, str]:
    """Confere se a caixa @gmail.com existe quando o servidor informa."""
    email = normalize_email(email)
    if "@" not in email:
        return False, "Informe um e-mail válido."

    domain = email.split("@", 1)[1]
    if domain != "gmail.com":
        return False, "Use um e-mail @gmail.com."

    mx_hosts, mx_state = lookup_mx(domain)
    if mx_state == "missing":
        return False, "Este e-mail não existe: o domínio não recebe mensagens no Gmail."
    if mx_state in ("timeout", "unavailable") and not mx_hosts:
        return True, "gmail"

    last_code = None
    for host in mx_hosts[:1]:
        last_code = _rcpt_status(host, email)
        if last_code is not None:
            break
        time.sleep(0.2)

    if last_code is None:
        return True, "gmail"
    if last_code == 250:
        return True, "gmail"
    if last_code in (550, 551, 552, 553, 554):
        return False, "Este e-mail não existe no Gmail."
    return True, "gmail"
