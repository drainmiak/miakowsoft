"""Input validation and target normalization."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class InputValidationError(ValueError):
    """Raised when a target cannot be accepted safely."""


EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!\$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{2,64}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\s()]{6,20}$")


def detect_type(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise InputValidationError("Empty target.")
    if "@" in value and EMAIL_RE.match(value):
        return "email"
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            raise InputValidationError("Private, loopback or reserved addresses are not accepted for public enrichment.")
        return "ip"
    except ValueError:
        pass
    if value.startswith("http://") or value.startswith("https://"):
        host = urlparse(value).hostname
        if host:
            return detect_type(host)
    cleaned_domain = value.lower().rstrip(".")
    if DOMAIN_RE.match(cleaned_domain):
        return "domain"
    if PHONE_RE.match(value.replace(" ", "")):
        return "phone"
    if USERNAME_RE.match(value):
        return "username"
    if len(value) >= 2:
        return "search"
    raise InputValidationError(f"Unable to classify target: {value!r}")


def normalize_target(raw: str, forced_type: str | None = None) -> tuple[str, str]:
    value = raw.strip()
    if not value:
        raise InputValidationError("Empty target.")
    if len(value) > 512:
        raise InputValidationError("Target exceeds maximum length.")
    t = forced_type if forced_type and forced_type != "auto" else detect_type(value)
    if t == "email":
        return value.lower(), "email"
    if t == "domain":
        return value.lower().rstrip("."), "domain"
    if t == "ip":
        return str(ipaddress.ip_address(value)), "ip"
    if t == "phone":
        digits = re.sub(r"[^\d+]", "", value)
        return digits, "phone"
    if t == "username":
        return value.lstrip("@"), "username"
    return value, "search"
