"""Public-source collectors for miakowsoft.

Each collector performs a real network request to a documented public endpoint,
returns structured observations, and never fabricates success.
"""

from __future__ import annotations

import json
import re
import socket
from typing import Any, Callable
from urllib.parse import quote, quote_plus, urlencode

from miakowsoft.models import Observation, SourceResult, utc_now_iso
from miakowsoft.utils import http_get, http_get_json, timed


def _ok(source: str, records: list[dict[str, Any]], duration_ms: int, note: str = "") -> SourceResult:
    return SourceResult(source=source, status="ok", count=len(records), duration_ms=duration_ms, note=note, records=records)


def _empty(source: str, duration_ms: int, note: str = "") -> SourceResult:
    return SourceResult(source=source, status="empty", count=0, duration_ms=duration_ms, note=note or "No matching public data returned")


def _err(source: str, duration_ms: int, error: str) -> SourceResult:
    return SourceResult(source=source, status="error", count=0, duration_ms=duration_ms, error=error)


def _skip(source: str, reason: str) -> SourceResult:
    return SourceResult(source=source, status="skipped", count=0, duration_ms=0, note=reason)


def _obs(
    indicator: str,
    indicator_type: str,
    title: str,
    source: str,
    source_url: str = "",
    confidence: str = "observation",
    evidence: str = "",
    **extra: Any,
) -> dict[str, Any]:
    o = Observation(
        indicator=indicator,
        indicator_type=indicator_type,
        title=title,
        source=source,
        retrieved_at=utc_now_iso(),
        source_url=source_url,
        confidence=confidence,
        evidence=evidence,
        raw=extra,
    )
    d = o.to_dict()
    d.update(extra)
    return d


def source_dns_doh(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain",):
        return _skip("dns_doh", "Applicable only to domains")
    name = "dns_doh"
    def run() -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for qtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            url = f"https://cloudflare-dns.com/dns-query?name={quote(target)}&type={qtype}"
            status, data = http_get_json(url, headers={"Accept": "application/dns-json"}, timeout=10)
            if status != 200 or not isinstance(data, dict):
                continue
            answers = data.get("Answer") or []
            for ans in answers:
                data_val = ans.get("data", "")
                records.append(
                    _obs(
                        target,
                        "domain",
                        f"{qtype} {data_val}",
                        name,
                        source_url=url,
                        confidence="direct",
                        evidence=f"DNS {qtype} via Cloudflare DoH",
                        record_type=qtype,
                        value=data_val,
                        ttl=ans.get("TTL"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_rdap_domain(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("rdap_domain", "Applicable only to domains")
    name = "rdap_domain"
    def run() -> list[dict[str, Any]]:
        url = f"https://rdap.org/domain/{quote(target)}"
        status, data = http_get_json(url, timeout=8)
        if status == 404:
            return []
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"RDAP HTTP {status}")
        records: list[dict[str, Any]] = []
        handle = data.get("handle") or data.get("ldhName") or target
        records.append(
            _obs(
                target,
                "domain",
                f"RDAP handle {handle}",
                name,
                source_url=url,
                confidence="direct",
                evidence="RDAP registry response",
                handle=handle,
                status=data.get("status"),
                nameservers=[ns.get("ldhName") for ns in (data.get("nameservers") or []) if isinstance(ns, dict)],
            )
        )
        for ent in data.get("entities") or []:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles") or []
            vcard = ent.get("vcardArray")
            label = ", ".join(roles) if roles else "entity"
            records.append(
                _obs(
                    target,
                    "domain",
                    f"Entity: {label}",
                    name,
                    source_url=url,
                    confidence="direct",
                    evidence="RDAP entity",
                    roles=roles,
                    vcard=vcard,
                )
            )
        events = data.get("events") or []
        for ev in events:
            if isinstance(ev, dict):
                records.append(
                    _obs(
                        target,
                        "domain",
                        f"Event {ev.get('eventAction')}: {ev.get('eventDate')}",
                        name,
                        source_url=url,
                        confidence="direct",
                        evidence="RDAP event",
                        event=ev,
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_crtsh(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("crtsh", "Applicable only to domains")
    name = "crtsh"
    def run() -> list[dict[str, Any]]:
        url = f"https://crt.sh/?q=%25.{quote(target)}&output=json"
        status, data = http_get_json(url, timeout=10)
        if status != 200:
            raise ConnectionError(f"crt.sh HTTP {status}")
        if not isinstance(data, list):
            return []
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        for row in data[:800]:
            if not isinstance(row, dict):
                continue
            name_value = (row.get("name_value") or "").strip()
            for part in name_value.split("\n"):
                host = part.strip().lower().lstrip("*.")
                if not host or host in seen:
                    continue
                seen.add(host)
                records.append(
                    _obs(
                        host,
                        "subdomain",
                        f"Certificate name: {host}",
                        name,
                        source_url=f"https://crt.sh/?q={quote(host)}",
                        confidence="direct",
                        evidence="Certificate Transparency (crt.sh)",
                        issuer=row.get("issuer_name"),
                        not_before=row.get("not_before"),
                        not_after=row.get("not_after"),
                        parent_domain=target,
                    )
                )
                if len(records) >= 500:
                    return records
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_wayback_cdx(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "username", "search"):
        return _skip("wayback_cdx", "Not applicable")
    name = "wayback_cdx"
    query = target if target_type != "domain" else f"*.{target}/*"
    def run() -> list[dict[str, Any]]:
        params = urlencode({"url": query, "output": "json", "limit": "25", "fl": "timestamp,original,statuscode,mimetype"})
        url = f"https://web.archive.org/cdx/search/cdx?{params}"
        status, text, _ = http_get(url, timeout=9)
        if status != 200:
            raise ConnectionError(f"Wayback HTTP {status}")
        lines = [ln for ln in text.strip().splitlines() if ln.strip()]
        if not lines:
            return []
        try:
            rows = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(rows, list) or len(rows) < 2:
            return []
        header, *body = rows
        records: list[dict[str, Any]] = []
        for row in body[:25]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            ts, original, code, mime = row[0], row[1], row[2], row[3]
            records.append(
                _obs(
                    original,
                    "url",
                    f"Archived {ts}: {original}",
                    name,
                    source_url=f"https://web.archive.org/web/{ts}/{original}",
                    confidence="direct",
                    evidence="Internet Archive CDX",
                    timestamp=ts,
                    status_code=code,
                    mimetype=mime,
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_ip_whois(target: str, target_type: str) -> SourceResult:
    if target_type != "ip":
        return _skip("ip_whois", "Applicable only to IP addresses")
    name = "ip_whois"
    def run() -> list[dict[str, Any]]:
        url = f"https://ipwho.is/{quote(target)}"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, dict) or not data.get("success", True):
            if isinstance(data, dict) and data.get("success") is False:
                return []
            raise ConnectionError(f"ipwho.is HTTP {status}")
        records = [
            _obs(
                target,
                "ip",
                f"{data.get('city')}, {data.get('country')} ({data.get('org')})",
                name,
                source_url=url,
                confidence="observation",
                evidence="Public IP geolocation and ASN (ipwho.is)",
                country=data.get("country"),
                country_code=data.get("country_code"),
                region=data.get("region"),
                city=data.get("city"),
                org=data.get("org"),
                asn=data.get("asn"),
                isp=data.get("isp"),
                latitude=data.get("latitude"),
                longitude=data.get("longitude"),
            )
        ]
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_bgpview(target: str, target_type: str) -> SourceResult:
    if target_type != "ip":
        return _skip("bgpview", "Applicable only to IP addresses")
    name = "bgpview"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.bgpview.io/ip/{quote(target)}"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"BGPView HTTP {status}")
        payload = data.get("data") or {}
        records: list[dict[str, Any]] = []
        prefixes = payload.get("prefixes") or []
        for p in prefixes[:15]:
            if not isinstance(p, dict):
                continue
            asn = (p.get("asn") or {}).get("asn")
            name_asn = (p.get("asn") or {}).get("name")
            records.append(
                _obs(
                    target,
                    "ip",
                    f"Prefix {p.get('prefix')} ASN{asn} {name_asn}",
                    name,
                    source_url=url,
                    confidence="direct",
                    evidence="BGPView public BGP data",
                    prefix=p.get("prefix"),
                    asn=asn,
                    asn_name=name_asn,
                    description=p.get("name") or p.get("description"),
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_otx(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "ip"):
        return _skip("otx", "Applicable to domain or IP")
    name = "otx"
    section = "domain" if target_type == "domain" else "IPv4"
    def run() -> list[dict[str, Any]]:
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(target)}/general"
        status, data = http_get_json(url, timeout=8)
        if status == 404:
            return []
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"OTX HTTP {status}")
        records: list[dict[str, Any]] = []
        pulse_info = data.get("pulse_info") or {}
        count = pulse_info.get("count", 0)
        records.append(
            _obs(
                target,
                target_type,
                f"OTX pulses: {count}",
                name,
                source_url=f"https://otx.alienvault.com/indicator/{section.lower()}/{target}",
                confidence="observation",
                evidence="AlienVault OTX public indicator",
                pulse_count=count,
                reputation=data.get("reputation"),
                validation=data.get("validation"),
            )
        )
        for pulse in (pulse_info.get("pulses") or [])[:3]:
            if isinstance(pulse, dict):
                records.append(
                    _obs(
                        target,
                        target_type,
                        f"Pulse: {pulse.get('name')}",
                        name,
                        source_url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                        confidence="observation",
                        evidence="OTX pulse reference",
                        pulse_id=pulse.get("id"),
                        created=pulse.get("created"),
                        tags=pulse.get("tags"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_github_user(target: str, target_type: str) -> SourceResult:
    if target_type not in ("username", "email"):
        return _skip("github_user", "Applicable to username or email")
    name = "github_user"
    def run() -> list[dict[str, Any]]:
        if target_type == "username":
            url = f"https://api.github.com/users/{quote(target)}"
            status, data = http_get_json(url, timeout=12)
            if status == 404:
                return []
            if status != 200 or not isinstance(data, dict):
                raise ConnectionError(f"GitHub HTTP {status}")
            return [
                _obs(
                    target,
                    "username",
                    f"GitHub: {data.get('login')} ({data.get('name') or 'no name'})",
                    name,
                    source_url=data.get("html_url") or url,
                    confidence="direct",
                    evidence="GitHub public profile API",
                    login=data.get("login"),
                    name=data.get("name"),
                    company=data.get("company"),
                    blog=data.get("blog"),
                    location=data.get("location"),
                    bio=data.get("bio"),
                    public_repos=data.get("public_repos"),
                    followers=data.get("followers"),
                    created_at=data.get("created_at"),
                )
            ]
        url = f"https://api.github.com/search/users?q={quote_plus(target + ' in:email')}"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"GitHub search HTTP {status}")
        items = data.get("items") or []
        records = []
        for item in items[:5]:
            if isinstance(item, dict):
                records.append(
                    _obs(
                        item.get("login", ""),
                        "username",
                        f"GitHub user match: {item.get('login')}",
                        name,
                        source_url=item.get("html_url") or "",
                        confidence="indirect",
                        evidence="GitHub user search (email field public only if exposed)",
                        login=item.get("login"),
                        score=item.get("score"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_gitlab_user(target: str, target_type: str) -> SourceResult:
    if target_type != "username":
        return _skip("gitlab_user", "Applicable to username")
    name = "gitlab_user"
    def run() -> list[dict[str, Any]]:
        url = f"https://gitlab.com/api/v4/users?username={quote(target)}"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, list):
            raise ConnectionError(f"GitLab HTTP {status}")
        records = []
        for item in data[:5]:
            if isinstance(item, dict):
                records.append(
                    _obs(
                        target,
                        "username",
                        f"GitLab: {item.get('username')} ({item.get('name')})",
                        name,
                        source_url=item.get("web_url") or "",
                        confidence="direct",
                        evidence="GitLab public users API",
                        username=item.get("username"),
                        name=item.get("name"),
                        state=item.get("state"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_hackernews(target: str, target_type: str) -> SourceResult:
    if target_type not in ("username", "search"):
        return _skip("hackernews", "Applicable to username or search")
    name = "hackernews"
    def run() -> list[dict[str, Any]]:
        if target_type == "username":
            url = f"https://hacker-news.firebaseio.com/v0/user/{quote(target)}.json"
            status, data = http_get_json(url, timeout=10)
            if status != 200 or data is None:
                return []
            if not isinstance(data, dict):
                return []
            return [
                _obs(
                    target,
                    "username",
                    f"HN user {data.get('id')} karma {data.get('karma')}",
                    name,
                    source_url=f"https://news.ycombinator.com/user?id={target}",
                    confidence="direct",
                    evidence="Hacker News public user API",
                    karma=data.get("karma"),
                    created=data.get("created"),
                    about=data.get("about"),
                )
            ]
        url = f"https://hn.algolia.com/api/v1/search?query={quote_plus(target)}&hitsPerPage=10"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"HN Algolia HTTP {status}")
        records = []
        for hit in (data.get("hits") or [])[:10]:
            if isinstance(hit, dict):
                title = hit.get("title") or hit.get("story_title") or hit.get("comment_text", "")[:80]
                records.append(
                    _obs(
                        str(hit.get("objectID", "")),
                        "mention",
                        title or "HN hit",
                        name,
                        source_url=hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}",
                        confidence="observation",
                        evidence="HN Algolia public search",
                        author=hit.get("author"),
                        points=hit.get("points"),
                        created_at=hit.get("created_at"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_email_mx(target: str, target_type: str) -> SourceResult:
    if target_type != "email":
        return _skip("email_mx", "Applicable to email")
    name = "email_mx"
    def run() -> list[dict[str, Any]]:
        domain = target.split("@", 1)[-1]
        records: list[dict[str, Any]] = []
        try:
            answers = socket.getaddrinfo(domain, 25, type=socket.SOCK_STREAM)
            hosts = sorted({a[4][0] for a in answers})
            for h in hosts[:5]:
                records.append(
                    _obs(
                        domain,
                        "domain",
                        f"MX-capable host resolution: {h}",
                        name,
                        confidence="observation",
                        evidence="Local DNS resolution for mail domain",
                        host=h,
                    )
                )
        except socket.gaierror:
            pass
        try:
            import dns.resolver
            mx = dns.resolver.resolve(domain, "MX")
            for r in mx:
                records.append(
                    _obs(
                        domain,
                        "domain",
                        f"MX {r.exchange} pref {r.preference}",
                        name,
                        confidence="direct",
                        evidence="DNS MX lookup (dnspython if available)",
                        exchange=str(r.exchange),
                        preference=int(r.preference),
                    )
                )
        except Exception:
            pass
        if not records:
            records.append(
                _obs(
                    domain,
                    "domain",
                    f"Email domain {domain} (syntax accepted)",
                    name,
                    confidence="observation",
                    evidence="Local syntax and basic resolution check only; no mailbox probing",
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_gravatar(target: str, target_type: str) -> SourceResult:
    if target_type != "email":
        return _skip("gravatar", "Applicable to email")
    name = "gravatar"
    def run() -> list[dict[str, Any]]:
        import hashlib
        h = hashlib.md5(target.strip().lower().encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/{h}.json"
        status, data = http_get_json(url, timeout=10)
        if status == 404:
            return []
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"Gravatar HTTP {status}")
        entry = (data.get("entry") or [None])[0]
        if not isinstance(entry, dict):
            return []
        return [
            _obs(
                target,
                "email",
                f"Gravatar profile: {entry.get('displayName') or entry.get('preferredUsername')}",
                name,
                source_url=entry.get("profileUrl") or f"https://www.gravatar.com/{h}",
                confidence="direct",
                evidence="Gravatar public profile JSON",
                display_name=entry.get("displayName"),
                preferred_username=entry.get("preferredUsername"),
                about=entry.get("aboutMe"),
                current_location=entry.get("currentLocation"),
                urls=[u.get("value") for u in (entry.get("urls") or []) if isinstance(u, dict)],
            )
        ]
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_duckduckgo(target: str, target_type: str) -> SourceResult:
    if target_type not in ("search", "username", "domain", "email"):
        return _skip("duckduckgo", "Not used for this type")
    name = "duckduckgo"
    def run() -> list[dict[str, Any]]:
        q = target if target_type == "search" else f'"{target}"'
        url = f"https://api.duckduckgo.com/?{urlencode({'q': q, 'format': 'json', 'no_redirect': '1', 'no_html': '1'})}"
        status, data = http_get_json(url, timeout=12)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"DuckDuckGo HTTP {status}")
        records: list[dict[str, Any]] = []
        if data.get("AbstractText"):
            records.append(
                _obs(
                    target,
                    target_type,
                    data.get("Heading") or "Abstract",
                    name,
                    source_url=data.get("AbstractURL") or "",
                    confidence="observation",
                    evidence="DuckDuckGo Instant Answer",
                    abstract=data.get("AbstractText"),
                )
            )
        for topic in (data.get("RelatedTopics") or [])[:12]:
            if isinstance(topic, dict) and topic.get("Text"):
                records.append(
                    _obs(
                        target,
                        "mention",
                        topic.get("Text")[:120],
                        name,
                        source_url=topic.get("FirstURL") or "",
                        confidence="observation",
                        evidence="DuckDuckGo related topic",
                    )
                )
            elif isinstance(topic, dict) and "Topics" in topic:
                for sub in (topic.get("Topics") or [])[:4]:
                    if isinstance(sub, dict) and sub.get("Text"):
                        records.append(
                            _obs(
                                target,
                                "mention",
                                sub.get("Text")[:120],
                                name,
                                source_url=sub.get("FirstURL") or "",
                                confidence="observation",
                                evidence="DuckDuckGo nested topic",
                            )
                        )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_phone_basic(target: str, target_type: str) -> SourceResult:
    if target_type != "phone":
        return _skip("phone_basic", "Applicable to phone")
    name = "phone_basic"
    def run() -> list[dict[str, Any]]:
        digits = re.sub(r"[^\d]", "", target)
        records = [
            _obs(
                target,
                "phone",
                f"Normalized digits length {len(digits)}",
                name,
                confidence="observation",
                evidence="Local normalization only; no carrier lookup without API key",
                digit_count=len(digits),
                e164_candidate=target if target.startswith("+") else f"+{digits}",
            )
        ]
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_dns_google(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("dns_google", "Applicable only to domains")
    name = "dns_google"
    def run() -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for qtype in ("A", "AAAA", "MX", "NS", "TXT"):
            url = f"https://dns.google/resolve?name={quote(target)}&type={qtype}"
            status, data = http_get_json(url, timeout=10)
            if status != 200 or not isinstance(data, dict):
                continue
            for ans in data.get("Answer") or []:
                data_val = ans.get("data", "")
                records.append(
                    _obs(
                        target,
                        "domain",
                        f"{qtype} {data_val}",
                        name,
                        source_url=url,
                        confidence="direct",
                        evidence=f"DNS {qtype} via Google DoH",
                        record_type=qtype,
                        value=data_val,
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_rdap_ip(target: str, target_type: str) -> SourceResult:
    if target_type != "ip":
        return _skip("rdap_ip", "Applicable only to IP")
    name = "rdap_ip"
    def run() -> list[dict[str, Any]]:
        url = f"https://rdap.org/ip/{quote(target)}"
        status, data = http_get_json(url, timeout=8)
        if status == 404:
            return []
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"RDAP IP HTTP {status}")
        records = [
            _obs(
                target,
                "ip",
                f"RDAP network {data.get('name') or data.get('handle') or target}",
                name,
                source_url=url,
                confidence="direct",
                evidence="RDAP IP network registration",
                handle=data.get("handle"),
                name=data.get("name"),
                country=data.get("country"),
                start_address=data.get("startAddress"),
                end_address=data.get("endAddress"),
            )
        ]
        for ent in (data.get("entities") or [])[:6]:
            if isinstance(ent, dict):
                records.append(
                    _obs(
                        target,
                        "ip",
                        f"Entity roles: {', '.join(ent.get('roles') or [])}",
                        name,
                        source_url=url,
                        confidence="direct",
                        evidence="RDAP IP entity",
                        roles=ent.get("roles"),
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_threatfox(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "ip"):
        return _skip("threatfox", "Applicable to domain or IP")
    name = "threatfox"
    def run() -> list[dict[str, Any]]:
        import urllib.request as ureq
        import ssl as sslmod
        url = "https://threatfox-api.abuse.ch/api/v1/"
        body = json.dumps({"query": "search_ioc", "search_term": target}).encode("utf-8")
        req = ureq.Request(
            url,
            data=body,
            headers={"User-Agent": "miakowsoft/1.1.0", "Content-Type": "application/json"},
            method="POST",
        )
        ctx = sslmod.create_default_context()
        with ureq.urlopen(req, timeout=8, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if not isinstance(data, dict):
            return []
        if data.get("query_status") not in ("ok", "no_result"):
            raise ConnectionError(str(data.get("query_status")))
        records: list[dict[str, Any]] = []
        for row in (data.get("data") or [])[:20]:
            if not isinstance(row, dict):
                continue
            records.append(
                _obs(
                    row.get("ioc") or target,
                    target_type,
                    f"ThreatFox {row.get('threat_type')}: {row.get('malware')}",
                    name,
                    source_url="https://threatfox.abuse.ch/",
                    confidence="observation",
                    evidence="abuse.ch ThreatFox public IOC",
                    threat_type=row.get("threat_type"),
                    malware=row.get("malware"),
                    confidence_level=row.get("confidence_level"),
                    first_seen=row.get("first_seen"),
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_ht_hostsearch(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("ht_hostsearch", "Applicable only to domains")
    name = "ht_hostsearch"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(target)}"
        status, text, _ = http_get(url, timeout=8)
        if status != 200:
            raise ConnectionError(f"HackerTarget HTTP {status}")
        low = text.lower()
        if "error" in low and ("api count" in low or "limit" in low):
            raise ConnectionError("HackerTarget rate limit")
        records: list[dict[str, Any]] = []
        for line in text.strip().splitlines()[:200]:
            line = line.strip()
            if not line or "," not in line:
                continue
            host, ip = line.split(",", 1)
            host, ip = host.strip(), ip.strip()
            records.append(
                _obs(
                    host,
                    "subdomain",
                    f"{host} -> {ip}",
                    name,
                    source_url=url,
                    confidence="observation",
                    evidence="HackerTarget hostsearch public free tier",
                    ip=ip,
                    parent_domain=target,
                )
            )
            if ip:
                records.append(
                    _obs(
                        ip,
                        "ip",
                        f"Hosted subdomain {host}",
                        name,
                        source_url=url,
                        confidence="observation",
                        evidence="HackerTarget hostsearch IP",
                        subdomain=host,
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_ht_reverse(target: str, target_type: str) -> SourceResult:
    if target_type != "ip":
        return _skip("ht_reverse", "Applicable only to IP")
    name = "ht_reverse"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={quote(target)}"
        status, text, _ = http_get(url, timeout=8)
        if status != 200:
            raise ConnectionError(f"HackerTarget HTTP {status}")
        if "error" in text.lower() and len(text) < 120:
            raise ConnectionError(text.strip())
        records: list[dict[str, Any]] = []
        for line in text.strip().splitlines()[:150]:
            host = line.strip()
            if not host or " " in host:
                continue
            records.append(
                _obs(
                    host,
                    "domain",
                    f"Reverse IP host: {host}",
                    name,
                    source_url=url,
                    confidence="observation",
                    evidence="HackerTarget reverse IP lookup",
                    ip=target,
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_urlscan(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "ip"):
        return _skip("urlscan", "Applicable to domain or IP")
    name = "urlscan"
    def run() -> list[dict[str, Any]]:
        q = f"domain:{target}" if target_type == "domain" else f"ip:{target}"
        url = f"https://urlscan.io/api/v1/search/?q={quote_plus(q)}&size=40"
        status, data = http_get_json(url, timeout=8)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"urlscan HTTP {status}")
        records: list[dict[str, Any]] = []
        for row in (data.get("results") or [])[:40]:
            if not isinstance(row, dict):
                continue
            page = row.get("page") or {}
            task = row.get("task") or {}
            records.append(
                _obs(
                    page.get("domain") or page.get("url") or target,
                    "url",
                    f"urlscan: {page.get('url') or task.get('url')}",
                    name,
                    source_url=row.get("result") or "",
                    confidence="observation",
                    evidence="urlscan.io public search",
                    country=page.get("country"),
                    server=page.get("server"),
                    ip=page.get("ip"),
                    scanned_at=task.get("time"),
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_otx_passive_dns(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "ip"):
        return _skip("otx_passive_dns", "Applicable to domain or IP")
    name = "otx_passive_dns"
    section = "domain" if target_type == "domain" else "IPv4"
    def run() -> list[dict[str, Any]]:
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(target)}/passive_dns"
        status, data = http_get_json(url, timeout=9)
        if status == 404:
            return []
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"OTX passive DNS HTTP {status}")
        records: list[dict[str, Any]] = []
        for row in (data.get("passive_dns") or [])[:120]:
            if not isinstance(row, dict):
                continue
            hostname = row.get("hostname") or row.get("address") or ""
            address = row.get("address") or ""
            if hostname:
                records.append(
                    _obs(
                        hostname,
                        "domain" if not IP_LIKE_LOCAL(hostname) else "ip",
                        f"Passive DNS: {hostname} -> {address}",
                        name,
                        source_url=f"https://otx.alienvault.com/indicator/{section.lower()}/{target}",
                        confidence="observation",
                        evidence="AlienVault OTX passive DNS",
                        address=address,
                        record_type=row.get("record_type"),
                        first=row.get("first"),
                        last=row.get("last"),
                    )
                )
            if address and address != hostname:
                records.append(
                    _obs(
                        address,
                        "ip" if IP_LIKE_LOCAL(address) else "domain",
                        f"Passive DNS address {address} for {hostname or target}",
                        name,
                        source_url=f"https://otx.alienvault.com/indicator/{section.lower()}/{target}",
                        confidence="observation",
                        evidence="AlienVault OTX passive DNS address",
                        hostname=hostname,
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def IP_LIKE_LOCAL(value: str) -> bool:
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", value or ""))


def source_bufferover(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("bufferover", "Applicable only to domains")
    name = "bufferover"
    def run() -> list[dict[str, Any]]:
        url = f"https://dns.bufferover.run/dns?q=.{quote(target)}"
        status, data = http_get_json(url, timeout=9)
        if status != 200 or not isinstance(data, dict):
            raise ConnectionError(f"bufferover HTTP {status}")
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for key in ("FDNS_A", "RDNS"):
            for item in data.get(key) or []:
                if not isinstance(item, str):
                    continue
                parts = item.split(",", 1)
                if len(parts) == 2:
                    a, b = parts[0].strip(), parts[1].strip()
                else:
                    a, b = item.strip(), ""
                for host in (a, b):
                    host = host.lower().rstrip(".")
                    if not host or host in seen:
                        continue
                    if not (DOMAIN_LIKE_LOCAL(host) or IP_LIKE_LOCAL(host)):
                        continue
                    seen.add(host)
                    itype = "ip" if IP_LIKE_LOCAL(host) else "subdomain"
                    records.append(
                        _obs(
                            host,
                            itype,
                            f"bufferover {key}: {item[:120]}",
                            name,
                            source_url=url,
                            confidence="observation",
                            evidence="bufferover.run passive DNS",
                            parent_domain=target,
                        )
                    )
                    if len(records) >= 300:
                        return records
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def DOMAIN_LIKE_LOCAL(value: str) -> bool:
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$", value or ""))


def source_hackertarget_dns(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("ht_dns", "Applicable only to domains")
    name = "ht_dns"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.hackertarget.com/dnslookup/?q={quote(target)}"
        status, text, _ = http_get(url, timeout=8)
        if status != 200:
            raise ConnectionError(f"HackerTarget DNS HTTP {status}")
        if "error" in text.lower() and len(text) < 120:
            raise ConnectionError(text.strip())
        records: list[dict[str, Any]] = []
        for line in text.strip().splitlines()[:100]:
            line = line.strip()
            if not line:
                continue
            records.append(
                _obs(
                    target,
                    "domain",
                    line[:200],
                    name,
                    source_url=url,
                    confidence="observation",
                    evidence="HackerTarget DNS lookup",
                    raw_line=line,
                )
            )
            for token in re.split(r"[\s,]+", line):
                token = token.strip().rstrip(".")
                if IP_LIKE_LOCAL(token):
                    records.append(
                        _obs(
                            token,
                            "ip",
                            f"DNS value {token}",
                            name,
                            source_url=url,
                            confidence="observation",
                            evidence="HackerTarget DNS IP value",
                        )
                    )
                elif DOMAIN_LIKE_LOCAL(token) and token != target:
                    records.append(
                        _obs(
                            token,
                            "domain",
                            f"DNS name {token}",
                            name,
                            source_url=url,
                            confidence="observation",
                            evidence="HackerTarget DNS name value",
                        )
                    )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_certspotter(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("certspotter", "Applicable only to domains")
    name = "certspotter"
    def run() -> list[dict[str, Any]]:
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={quote(target)}&include_subdomains=true&expand=dns_names"
        )
        status, data = http_get_json(url, timeout=10)
        if status == 429:
            raise ConnectionError("certspotter rate limited")
        if status != 200 or not isinstance(data, list):
            raise ConnectionError(f"certspotter HTTP {status}")
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        for row in data[:200]:
            if not isinstance(row, dict):
                continue
            for host in row.get("dns_names") or []:
                if not isinstance(host, str):
                    continue
                host = host.strip().lower().lstrip("*.")
                if not host or host in seen:
                    continue
                seen.add(host)
                records.append(
                    _obs(
                        host,
                        "subdomain",
                        f"CertSpotter: {host}",
                        name,
                        source_url="https://sslmate.com/certspotter/",
                        confidence="direct",
                        evidence="CertSpotter certificate transparency",
                        parent_domain=target,
                        not_before=row.get("not_before"),
                        not_after=row.get("not_after"),
                    )
                )
                if len(records) >= 400:
                    return records
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_ht_whois(target: str, target_type: str) -> SourceResult:
    if target_type not in ("domain", "ip"):
        return _skip("ht_whois", "Applicable to domain or IP")
    name = "ht_whois"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.hackertarget.com/whois/?q={quote(target)}"
        status, text, _ = http_get(url, timeout=16)
        if status != 200:
            raise ConnectionError(f"HackerTarget whois HTTP {status}")
        if "error" in text.lower() and len(text) < 120:
            raise ConnectionError(text.strip())
        records: list[dict[str, Any]] = []
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            return []
        summary = " | ".join(lines[:6])[:240]
        records.append(
            _obs(
                target,
                target_type,
                f"WHOIS: {summary}",
                name,
                source_url=url,
                confidence="observation",
                evidence="HackerTarget WHOIS text",
                whois_lines=lines[:40],
            )
        )
        for ln in lines[:40]:
            low = ln.lower()
            if ":" not in ln:
                continue
            key, val = ln.split(":", 1)
            val = val.strip()
            if not val:
                continue
            if "name server" in low or key.lower().startswith("nserver"):
                for token in re.split(r"[\s,]+", val):
                    token = token.strip().rstrip(".").lower()
                    if DOMAIN_LIKE_LOCAL(token):
                        records.append(
                            _obs(
                                token,
                                "domain",
                                f"WHOIS nameserver {token}",
                                name,
                                source_url=url,
                                confidence="observation",
                                evidence="WHOIS nameserver field",
                            )
                        )
            if any(x in low for x in ("orgname", "organization", "org:", "registrant organisation", "registrant organization")):
                records.append(
                    _obs(
                        target,
                        target_type,
                        f"WHOIS org: {val[:120]}",
                        name,
                        source_url=url,
                        confidence="observation",
                        evidence="WHOIS organization field",
                        organization=val,
                    )
                )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_ht_sharedns(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("ht_sharedns", "Applicable only to domains")
    name = "ht_sharedns"
    def run() -> list[dict[str, Any]]:
        url = f"https://api.hackertarget.com/findshareddns/?q={quote(target)}"
        status, text, _ = http_get(url, timeout=16)
        if status != 200:
            raise ConnectionError(f"HackerTarget sharedns HTTP {status}")
        if "error" in text.lower() and len(text) < 120:
            raise ConnectionError(text.strip())
        records: list[dict[str, Any]] = []
        for line in text.strip().splitlines()[:120]:
            host = line.strip().lower().rstrip(".")
            if not host or not DOMAIN_LIKE_LOCAL(host):
                continue
            records.append(
                _obs(
                    host,
                    "domain",
                    f"Shared DNS host: {host}",
                    name,
                    source_url=url,
                    confidence="observation",
                    evidence="HackerTarget findshareddns",
                    seed=target,
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


def source_anubis(target: str, target_type: str) -> SourceResult:
    if target_type != "domain":
        return _skip("anubis", "Applicable only to domains")
    name = "anubis"
    def run() -> list[dict[str, Any]]:
        url = f"https://jldc.me/anubis/subdomains/{quote(target)}"
        status, data = http_get_json(url, timeout=10)
        if status != 200:
            raise ConnectionError(f"anubis HTTP {status}")
        if not isinstance(data, list):
            return []
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in data[:400]:
            host = str(item).strip().lower().rstrip(".")
            if not host or host in seen or not DOMAIN_LIKE_LOCAL(host):
                continue
            seen.add(host)
            records.append(
                _obs(
                    host,
                    "subdomain",
                    f"Anubis subdomain: {host}",
                    name,
                    source_url=url,
                    confidence="observation",
                    evidence="jldc.me Anubis subdomain aggregate",
                    parent_domain=target,
                )
            )
        return records
    try:
        records, ms = timed(run)()
        return _ok(name, records, ms) if records else _empty(name, ms)
    except Exception as exc:
        return _err(name, 0, str(exc))


SOURCE_CATALOG: list[dict[str, Any]] = [
    {"name": "dns_doh", "categories": ["domain"], "description": "DNS records via Cloudflare DNS-over-HTTPS", "documentation_url": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/", "requires": []},
    {"name": "dns_google", "categories": ["domain"], "description": "DNS records via Google DNS-over-HTTPS", "documentation_url": "https://developers.google.com/speed/public-dns/docs/doh", "requires": []},
    {"name": "rdap_domain", "categories": ["domain"], "description": "RDAP domain registration data", "documentation_url": "https://about.rdap.org/", "requires": []},
    {"name": "rdap_ip", "categories": ["ip"], "description": "RDAP IP network registration", "documentation_url": "https://about.rdap.org/", "requires": []},
    {"name": "crtsh", "categories": ["domain"], "description": "Certificate Transparency names from crt.sh", "documentation_url": "https://crt.sh/", "requires": []},
    {"name": "wayback_cdx", "categories": ["domain", "username", "search"], "description": "Internet Archive CDX historical captures", "documentation_url": "https://archive.org/help/wayback_api.php", "requires": []},
    {"name": "ip_whois", "categories": ["ip"], "description": "Public IP geolocation and org (ipwho.is)", "documentation_url": "https://ipwho.is/", "requires": []},
    {"name": "bgpview", "categories": ["ip"], "description": "BGP prefixes and ASN via BGPView", "documentation_url": "https://bgpview.docs.apiary.io/", "requires": []},
    {"name": "otx", "categories": ["domain", "ip"], "description": "AlienVault OTX public indicator summary", "documentation_url": "https://otx.alienvault.com/", "requires": []},
    {"name": "threatfox", "categories": ["domain", "ip"], "description": "abuse.ch ThreatFox IOC search", "documentation_url": "https://threatfox.abuse.ch/", "requires": []},
    {"name": "ht_hostsearch", "categories": ["domain"], "description": "HackerTarget hostsearch subdomains and IPs", "documentation_url": "https://hackertarget.com/", "requires": []},
    {"name": "ht_reverse", "categories": ["ip"], "description": "HackerTarget reverse IP lookup", "documentation_url": "https://hackertarget.com/", "requires": []},
    {"name": "urlscan", "categories": ["domain", "ip"], "description": "urlscan.io public search results", "documentation_url": "https://urlscan.io/docs/api/", "requires": []},
    {"name": "otx_passive_dns", "categories": ["domain", "ip"], "description": "AlienVault OTX passive DNS history", "documentation_url": "https://otx.alienvault.com/", "requires": []},
    {"name": "bufferover", "categories": ["domain"], "description": "bufferover.run passive DNS (FDNS/RDNS)", "documentation_url": "https://tls.bufferover.run/", "requires": []},
    {"name": "ht_dns", "categories": ["domain"], "description": "HackerTarget DNS lookup", "documentation_url": "https://hackertarget.com/", "requires": []},
    {"name": "certspotter", "categories": ["domain"], "description": "CertSpotter certificate transparency issuances", "documentation_url": "https://sslmate.com/certspotter/", "requires": []},
    {"name": "ht_whois", "categories": ["domain", "ip"], "description": "HackerTarget WHOIS text", "documentation_url": "https://hackertarget.com/", "requires": []},
    {"name": "ht_sharedns", "categories": ["domain"], "description": "HackerTarget shared DNS hosts", "documentation_url": "https://hackertarget.com/", "requires": []},
    {"name": "anubis", "categories": ["domain"], "description": "Anubis aggregated subdomains (jldc.me)", "documentation_url": "https://jldc.me/anubis/", "requires": []},
    {"name": "github_user", "categories": ["username", "email"], "description": "GitHub public user profile or search", "documentation_url": "https://docs.github.com/en/rest", "requires": []},
    {"name": "gitlab_user", "categories": ["username"], "description": "GitLab public user lookup", "documentation_url": "https://docs.gitlab.com/ee/api/users.html", "requires": []},
    {"name": "hackernews", "categories": ["username", "search"], "description": "Hacker News user or Algolia search", "documentation_url": "https://github.com/HackerNews/API", "requires": []},
    {"name": "email_mx", "categories": ["email"], "description": "Email domain MX and resolution checks", "documentation_url": "", "requires": []},
    {"name": "gravatar", "categories": ["email"], "description": "Gravatar public profile by email hash", "documentation_url": "https://en.gravatar.com/site/implement/profiles/json/", "requires": []},
    {"name": "duckduckgo", "categories": ["search", "username", "domain", "email"], "description": "DuckDuckGo Instant Answer API", "documentation_url": "https://duckduckgo.com/api", "requires": []},
    {"name": "phone_basic", "categories": ["phone"], "description": "Local phone number normalization", "documentation_url": "", "requires": []},
]


COLLECTORS: dict[str, Callable[[str, str], SourceResult]] = {
    "dns_doh": source_dns_doh,
    "dns_google": source_dns_google,
    "rdap_domain": source_rdap_domain,
    "rdap_ip": source_rdap_ip,
    "crtsh": source_crtsh,
    "wayback_cdx": source_wayback_cdx,
    "ip_whois": source_ip_whois,
    "bgpview": source_bgpview,
    "otx": source_otx,
    "threatfox": source_threatfox,
    "ht_hostsearch": source_ht_hostsearch,
    "ht_reverse": source_ht_reverse,
    "urlscan": source_urlscan,
    "otx_passive_dns": source_otx_passive_dns,
    "bufferover": source_bufferover,
    "ht_dns": source_hackertarget_dns,
    "certspotter": source_certspotter,
    "ht_whois": source_ht_whois,
    "ht_sharedns": source_ht_sharedns,
    "anubis": source_anubis,
    "github_user": source_github_user,
    "gitlab_user": source_gitlab_user,
    "hackernews": source_hackernews,
    "email_mx": source_email_mx,
    "gravatar": source_gravatar,
    "duckduckgo": source_duckduckgo,
    "phone_basic": source_phone_basic,
}


def collectors_for(target_type: str) -> list[str]:
    names = []
    for entry in SOURCE_CATALOG:
        if target_type in entry["categories"]:
            names.append(entry["name"])
    return names
