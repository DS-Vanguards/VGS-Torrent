from datetime import datetime, timedelta
import secrets

from flask import make_response, request

from extensions import db
from hardening import client_ip
from models import DeviceBlock

COOKIE_NAME = "vt_machine"
ATTEMPT_LIMIT = 4
SHORT_BLOCK = timedelta(minutes=5)
LONG_BLOCK = timedelta(days=1)
RECURRENCE_LIMIT = 6


def parse_block_duration(amount, unit: str):
    try:
        value = int(amount)
    except (TypeError, ValueError):
        return None
    if value < 1 or value > 999:
        return None
    unit = (unit or "").strip().lower()
    if unit in ("hora", "horas", "h"):
        return timedelta(hours=value)
    if unit in ("dia", "dias", "d"):
        return timedelta(days=value)
    if unit in ("semana", "semanas", "w"):
        return timedelta(weeks=value)
    if unit in ("mes", "mês", "meses", "m"):
        return timedelta(days=30 * value)
    if unit in ("ano", "anos", "y"):
        return timedelta(days=365 * value)
    return None


def _new_token() -> str:
    return secrets.token_hex(24)


def _attach_cookie(response, token: str):
    secure = request.is_secure or bool(request.headers.get("X-Forwarded-Proto") == "https")
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=60 * 60 * 24 * 400,
        httponly=True,
        samesite="Lax",
        secure=secure,
    )
    return response


def ensure_machine() -> DeviceBlock:
    token = (request.cookies.get(COOKIE_NAME) or "").strip()
    ip = client_ip()
    device = DeviceBlock.query.filter_by(token=token).first() if token else None
    if not device:
        device = DeviceBlock(token=token or _new_token(), ip=ip or "", attempt_count=0, strike_level=0)
        db.session.add(device)
        db.session.commit()
        return device
    if ip and device.ip != ip:
        device.ip = ip
        device.updated_at = datetime.utcnow()
        db.session.commit()
    return device


def attach_machine_cookie(response, token: str):
    current = (request.cookies.get(COOKIE_NAME) or "").strip()
    if not token or current == token:
        return response
    return _attach_cookie(response, token)


def identify_device(persist: bool = True) -> DeviceBlock:
    token = (request.cookies.get(COOKIE_NAME) or "").strip()
    ip = client_ip()
    device = None
    if token:
        device = DeviceBlock.query.filter_by(token=token).first()
    if not device and ip:
        device = (
            DeviceBlock.query.filter(
                DeviceBlock.ip == ip,
                DeviceBlock.blocked_until > datetime.utcnow(),
            )
            .order_by(DeviceBlock.updated_at.desc())
            .first()
        )
    if not device:
        device = DeviceBlock(token=token or _new_token(), ip=ip, attempt_count=0, strike_level=0)
        if persist:
            db.session.add(device)
            db.session.commit()
    elif persist and ip and device.ip != ip:
        device.ip = ip
        db.session.commit()
    return device


def with_device_cookie(html_or_response, device: DeviceBlock):
    response = make_response(html_or_response)
    return _attach_cookie(response, device.token)


def refresh_block_state(device: DeviceBlock) -> DeviceBlock:
    if device.id is None:
        return device
    if device.blocked_until and device.blocked_until <= datetime.utcnow():
        device.blocked_until = None
        device.attempt_count = 0
        db.session.commit()
    return device


def register_attempt(device: DeviceBlock) -> DeviceBlock:
    if device.id is None:
        db.session.add(device)
        db.session.commit()
    refresh_block_state(device)
    if device.is_blocked():
        return device
    device.attempt_count = (device.attempt_count or 0) + 1
    device.updated_at = datetime.utcnow()
    if device.attempt_count >= ATTEMPT_LIMIT:
        device.strike_level = (device.strike_level or 0) + 1
        if device.strike_level >= RECURRENCE_LIMIT:
            device.blocked_until = datetime.utcnow() + LONG_BLOCK
        else:
            device.blocked_until = datetime.utcnow() + SHORT_BLOCK
        device.attempt_count = 0
    db.session.commit()
    return device


def blocked_page_context(device: DeviceBlock) -> dict:
    if device.strike_level >= RECURRENCE_LIMIT:
        return {
            "title": "Acesso bloqueado",
            "severe": True,
        }
    return {
        "title": "Acesso negado",
        "severe": False,
    }
