"""Pull the repo-hosted feeds.json and fetch each source for current advisories.

Stdlib-only (urllib + xml.etree) so the PyInstaller bundle stays slim and no
extra deps are needed at runtime. Every fetch is short-timeout and errors are
captured as findings rather than raised — the scanner should never crash
because an external feed is down.
"""

import json
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from html import unescape
from xml.etree import ElementTree as ET

from .runner import Finding, Severity, Status, truncate

FEEDS_INDEX_URL = "https://raw.githubusercontent.com/jaa-git/VulnFinder/main/feeds.json"
USER_AGENT = "VulnFinder/0.2 (+https://github.com/jaa-git/VulnFinder)"
DEFAULT_TIMEOUT = 8

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def _http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/rss+xml, application/xml, */*",
    })
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        raw = r.read()
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def run(offline: bool = False, index_url: str | None = None):
    if offline:
        return [Finding(
            name="Online vulnerability feeds skipped (--offline)",
            status=Status.INFO,
            severity=Severity.INFO,
            description="Scanner was run with --offline; no external advisory sources were queried.",
        )]

    idx_url = index_url or FEEDS_INDEX_URL
    try:
        text = _http_get(idx_url)
        index = json.loads(text)
    except Exception as e:
        return [Finding(
            name="Vulnerability feed index unreachable",
            status=Status.WARN,
            severity=Severity.INFO,
            description="Could not download feeds.json from the VulnFinder repository.",
            evidence=f"{type(e).__name__}: {e}\nURL: {idx_url}",
            recommendation="Check internet connectivity, or run with --offline to suppress this section.",
        )]

    max_items = int(index.get("max_items_per_source", 25))
    sources = index.get("sources", [])

    findings: list[Finding] = []
    findings.append(Finding(
        name=f"Vulnerability feed index loaded ({len(sources)} sources)",
        status=Status.INFO,
        severity=Severity.INFO,
        description=index.get("description", ""),
        evidence=f"Index: {idx_url}\nSources: " + ", ".join(s.get("name", "?") for s in sources),
    ))

    for src in sources:
        findings.extend(_process_source(src, max_items))
    return findings


def _process_source(src: dict, max_items: int) -> list[Finding]:
    name = src.get("name", "Unknown source")
    url = src.get("url", "")
    stype = (src.get("type") or "").lower()
    sev = _SEV_MAP.get(src.get("severity", "MEDIUM").upper(), Severity.MEDIUM)
    note = src.get("note", "")

    url = _expand_placeholders(url, src)

    try:
        raw = _http_get(url)
    except Exception as e:
        return [Finding(
            name=f"Feed unreachable: {name}",
            status=Status.ERROR,
            severity=Severity.INFO,
            description="The feed URL could not be fetched.",
            evidence=f"{type(e).__name__}: {e}\nURL: {url}",
        )]

    try:
        if stype == "cisa_kev":
            return _render_kev(name, raw, src, sev, note, max_items)
        if stype == "rss":
            return _render_rss(name, raw, src, sev, note, max_items)
        if stype == "nvd":
            return _render_nvd(name, raw, src, sev, note, max_items)
        return [Finding(
            name=f"Unknown feed type '{stype}': {name}",
            status=Status.WARN,
            severity=Severity.INFO,
            evidence=f"URL: {url}",
        )]
    except Exception as e:
        return [Finding(
            name=f"Feed parse error: {name}",
            status=Status.ERROR,
            severity=Severity.INFO,
            description="Fetched the feed but could not parse its contents.",
            evidence=f"{type(e).__name__}: {e}\nURL: {url}\nFirst 400 bytes: {raw[:400]}",
        )]


def _expand_placeholders(url: str, src: dict) -> str:
    if "{start_iso}" in url or "{end_iso}" in url:
        days = int(src.get("dynamic_since_days", 30))
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        url = url.replace("{start_iso}", start.strftime("%Y-%m-%dT%H:%M:%S.000"))
        url = url.replace("{end_iso}", end.strftime("%Y-%m-%dT%H:%M:%S.000"))
    return url


def _render_kev(name, raw, src, sev, note, max_items):
    data = json.loads(raw)
    vulns = data.get("vulnerabilities", [])
    flt = src.get("filter", {}) or {}
    vendor_sub = (flt.get("vendor_contains") or "").lower()
    if vendor_sub:
        vulns = [v for v in vulns if vendor_sub in (v.get("vendorProject", "") + " " + v.get("product", "")).lower()]

    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    recent = vulns[:max_items]

    if not recent:
        return [Finding(
            name=f"{name}: no matching entries",
            status=Status.INFO,
            severity=Severity.INFO,
            description=note,
        )]

    lines = []
    for v in recent:
        cve = v.get("cveID", "?")
        date_added = v.get("dateAdded", "?")
        product = f"{v.get('vendorProject','?')} {v.get('product','?')}".strip()
        title = v.get("vulnerabilityName", "")
        due = v.get("dueDate", "")
        lines.append(f"{cve}  [{date_added}]  {product} — {title}  (patch by {due})")

    return [Finding(
        name=f"{name} — {len(recent)} actively-exploited Microsoft CVEs",
        status=Status.WARN,
        severity=sev,
        description=(note or "Microsoft vulnerabilities known to be exploited in the wild. Patch any that apply to this host immediately."),
        evidence="\n".join(lines),
        recommendation="Cross-reference each CVE against your patch level (Get-HotFix, winver). Apply the corresponding Microsoft patch or mitigation.",
    )]


def _render_rss(name, raw, src, sev, note, max_items):
    items = _parse_rss(raw)
    flt = src.get("filter", {}) or {}
    keywords = [k.lower() for k in (flt.get("title_contains_any") or [])]
    if keywords:
        items = [it for it in items if any(k in it["title"].lower() or k in it.get("summary", "").lower() for k in keywords)]

    items = items[:max_items]
    if not items:
        return [Finding(
            name=f"{name}: no matching items",
            status=Status.INFO,
            severity=Severity.INFO,
            description=note,
        )]

    lines = []
    for it in items:
        date = it.get("date", "")
        title = it["title"]
        link = it.get("link", "")
        lines.append(f"[{date}] {title}\n    {link}")

    return [Finding(
        name=f"{name} — {len(items)} recent items",
        status=Status.INFO,
        severity=sev,
        description=note or "Recent items from this RSS feed, filtered for Windows / Microsoft relevance.",
        evidence="\n".join(lines),
    )]


def _parse_rss(raw: str) -> list[dict]:
    cleaned = re.sub(r"^\uFEFF?\s*", "", raw)
    # Strip control chars that corrupt XML parsers
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", cleaned)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return _parse_rss_regex(cleaned)

    out = []
    for ns_item in root.iter():
        tag = ns_item.tag.split("}", 1)[-1].lower()
        if tag in ("item", "entry"):
            title = _child_text(ns_item, "title")
            link = _child_text(ns_item, "link")
            if not link:
                for c in ns_item:
                    if c.tag.split("}", 1)[-1].lower() == "link":
                        link = c.attrib.get("href", "") or (c.text or "")
                        break
            date = (_child_text(ns_item, "pubDate")
                    or _child_text(ns_item, "published")
                    or _child_text(ns_item, "updated"))
            summary = (_child_text(ns_item, "description")
                       or _child_text(ns_item, "summary")
                       or _child_text(ns_item, "content"))
            out.append({
                "title": _clean(title),
                "link": (link or "").strip(),
                "date": _short_date(date),
                "summary": _clean(summary),
            })
    return out


def _parse_rss_regex(raw: str) -> list[dict]:
    """Fallback parser: extract <item>...</item> blocks with regex.

    Used when the feed isn't well-formed XML (MSRC has done this historically).
    """
    out = []
    blocks = re.findall(r"<item\b[^>]*>(.*?)</item>", raw, flags=re.DOTALL | re.IGNORECASE)
    if not blocks:
        blocks = re.findall(r"<entry\b[^>]*>(.*?)</entry>", raw, flags=re.DOTALL | re.IGNORECASE)
    for block in blocks:
        title = _rx_tag(block, "title")
        link = _rx_tag(block, "link")
        if not link:
            m = re.search(r"<link[^>]*href=['\"]([^'\"]+)['\"]", block, flags=re.IGNORECASE)
            if m:
                link = m.group(1)
        date = (_rx_tag(block, "pubDate") or _rx_tag(block, "published")
                or _rx_tag(block, "updated") or _rx_tag(block, "dc:date"))
        summary = _rx_tag(block, "description") or _rx_tag(block, "summary") or _rx_tag(block, "content")
        out.append({
            "title": _clean(title),
            "link": (link or "").strip(),
            "date": _short_date(date),
            "summary": _clean(summary),
        })
    return out


def _rx_tag(block: str, tag: str) -> str:
    m = re.search(rf"<{tag}\b[^>]*>(.*?)</{tag}>", block, flags=re.DOTALL | re.IGNORECASE)
    if not m:
        return ""
    val = m.group(1).strip()
    val = re.sub(r"^<!\[CDATA\[(.*)\]\]>\s*$", r"\1", val, flags=re.DOTALL)
    return val


def _child_text(elem, name):
    for c in elem:
        if c.tag.split("}", 1)[-1].lower() == name.lower():
            return (c.text or "").strip()
    return ""


def _clean(s: str) -> str:
    s = unescape(s or "")
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _short_date(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:len(fmt) + 5], fmt).strftime("%Y-%m-%d")
        except Exception:
            continue
    return s[:10]


def _render_nvd(name, raw, src, sev, note, max_items):
    data = json.loads(raw)
    cves = data.get("vulnerabilities", [])[:max_items]
    if not cves:
        return [Finding(
            name=f"{name}: no results",
            status=Status.INFO,
            severity=Severity.INFO,
            description=note,
        )]
    lines = []
    for wrap in cves:
        c = wrap.get("cve", {})
        cve_id = c.get("id", "?")
        pub = c.get("published", "")[:10]
        score = "?"
        try:
            m = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in m and m[key]:
                    md = m[key][0].get("cvssData", {})
                    score = f"{md.get('baseScore','?')} ({md.get('baseSeverity','?')})"
                    break
        except Exception:
            pass
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        lines.append(f"{cve_id}  [{pub}]  CVSS {score}\n    {truncate(desc, 220)}")
    return [Finding(
        name=f"{name} — {len(cves)} CVEs",
        status=Status.INFO,
        severity=sev,
        description=note,
        evidence="\n".join(lines),
        recommendation="Review each CVE against installed software; apply vendor patches where applicable.",
    )]
