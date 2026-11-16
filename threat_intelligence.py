"""Bounded EPSS/KEV enrichment; failure preserves explicit unknown status.

Network access is opt-in via VULNX_THREAT_ENRICHMENT=1; no telemetry is sent
without an operator decision. Batch requests avoid per-finding HTTP calls.

Cache design (v2): freshness is tracked *per source* and, for EPSS, *per CVE*.
A CVE that has never been fetched (or whose entry expired) is always eligible
for refresh, and a failed refresh never overwrites good cached data nor resets
a freshness timestamp, so a transient outage cannot block retries.
"""
from __future__ import annotations
import json
import re
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.parse import urlencode

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

EPSS_URL = 'https://api.first.org/data/v1/epss'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CACHE_FILE = Path(__file__).resolve().parent / 'data' / 'threat_intelligence_cache.json'
CACHE_TTL = timedelta(hours=24)
EPSS_BATCH = 100
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}')


def _read_cache():
    try:
        obj = json.loads(CACHE_FILE.read_text(encoding='utf-8'))
        return obj if isinstance(obj, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_cache(cache):
    """Atomic write so a crash cannot leave a truncated cache file."""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_FILE.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(cache), encoding='utf-8')
        tmp.replace(CACHE_FILE)
    except OSError:
        pass


def _get_json(url):
    req = Request(url, headers={'User-Agent': 'VulnX/2.0 vulnerability-prioritization', 'Accept': 'application/json'})
    with urlopen(req, timeout=12) as resp:
        if resp.status != 200:
            raise RuntimeError(f'HTTP {resp.status}')
        data = resp.read(15_000_001)
        if len(data) > 15_000_000:
            raise ValueError('Threat intelligence response too large')
        return json.loads(data)


def _parse_time(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _is_fresh(fetched_at, now):
    parsed = _parse_time(fetched_at)
    return parsed is not None and (now - parsed) < CACHE_TTL


def _normalize_cache(raw):
    """Return the v2 structure; migrate the legacy single-timestamp format."""
    if isinstance(raw.get('kev'), dict) and 'data' in raw['kev'] and 'fetched_at' in raw['kev']:
        epss = raw.get('epss') if isinstance(raw.get('epss'), dict) else {}
        return {'version': 2, 'kev': raw['kev'], 'epss': epss}
    legacy_time = raw.get('fetched_at')
    legacy_kev = raw.get('kev')
    legacy_epss = raw.get('epss') if isinstance(raw.get('epss'), dict) else {}
    kev = {'fetched_at': legacy_time, 'data': legacy_kev} if isinstance(legacy_kev, dict) else {'fetched_at': None, 'data': None}
    epss = {cve: dict(entry, fetched_at=legacy_time) for cve, entry in legacy_epss.items() if isinstance(entry, dict)}
    return {'version': 2, 'kev': kev, 'epss': epss}


def _refresh_kev(cache, now):
    """Replace KEV data only on success; keep the previous data (now stale) on failure."""
    try:
        result = _get_json(KEV_URL)
        data = {str(entry['cveID']).upper(): entry.get('dateAdded') for entry in result.get('vulnerabilities', [])}
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, AttributeError):
        return False
    cache['kev'] = {'fetched_at': now.isoformat(), 'data': data}
    return True


def _refresh_epss(cache, cves, now):
    """Fetch EPSS for the given CVEs in batches; a failed batch affects only itself."""
    changed = False
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start:start + EPSS_BATCH]
        try:
            result = _get_json(EPSS_URL + '?' + urlencode({'cve': ','.join(batch)}))
            returned = {}
            for entry in result.get('data', []):
                returned[str(entry['cve']).upper()] = {
                    'probability': float(entry['epss']), 'percentile': float(entry['percentile']),
                    'date': entry.get('date'), 'fetched_at': now.isoformat()}
        except (ValueError, KeyError, TypeError, OSError, RuntimeError, AttributeError):
            continue  # leave these CVEs untouched so they are retried next call
        for cve in batch:
            # FIRST omits CVEs it has no score for; remember that so we do not re-ask every call.
            cache['epss'][cve] = returned.get(cve, {'missing': True, 'fetched_at': now.isoformat()})
        changed = True
    return changed


def get_cached_epss(cve: str) -> dict | None:
    """Return cached EPSS record for a CVE if available."""
    if not cve or not _CVE_RE.fullmatch(str(cve).strip().upper()):
        return None
    cve_clean = str(cve).strip().upper()
    cache = _normalize_cache(_read_cache())
    entry = cache.get('epss', {}).get(cve_clean)
    if isinstance(entry, dict) and not entry.get('missing') and 'probability' in entry:
        now = datetime.now(timezone.utc)
        epss_fresh = _is_fresh(entry.get('fetched_at'), now)
        return {
            'probability': entry.get('probability'),
            'percentile': entry.get('percentile'),
            'date': entry.get('date'),
            'status': 'available' if epss_fresh else 'stale',
            'fetched_at': entry.get('fetched_at')
        }
    return None


def enrich_findings(findings):
    """Return copied findings; no scan failure if remote services are offline."""
    rows = [dict(f) for f in findings]
    cves = sorted({str(f.get('cve') or '').upper() for f in rows if _CVE_RE.fullmatch(str(f.get('cve') or '').upper())})
    if not cves:
        return rows
    cache = _normalize_cache(_read_cache())
    now = datetime.now(timezone.utc)

    enrichment_enabled = (
        os.getenv('VULNX_THREAT_ENRICHMENT', '0') in ('1', 'true', 'True')
        or os.getenv('VULNGRAPH_THREAT_ENRICHMENT', '0') in ('1', 'true', 'True')
    )
    if enrichment_enabled:
        changed = False
        if not _is_fresh(cache['kev'].get('fetched_at'), now) or not isinstance(cache['kev'].get('data'), dict):
            changed |= _refresh_kev(cache, now)
        needed = [c for c in cves if not (isinstance(cache['epss'].get(c), dict)
                                           and _is_fresh(cache['epss'][c].get('fetched_at'), now))]
        if needed:
            changed |= _refresh_epss(cache, needed, now)
        if changed:
            _write_cache(cache)

    kev_data = cache['kev'].get('data')
    kev_time = cache['kev'].get('fetched_at')
    kev_fresh = isinstance(kev_data, dict) and _is_fresh(kev_time, now)
    for f in rows:
        cve = str(f.get('cve') or '').upper()
        if cve not in cves:
            continue
        entry = cache['epss'].get(cve)
        has_data = isinstance(entry, dict) and not entry.get('missing') and 'probability' in entry
        epss_fresh = has_data and _is_fresh(entry.get('fetched_at'), now)
        if epss_fresh:
            f.update(
                epss_probability=entry.get('probability'),
                epss_percentile=entry.get('percentile'),
                epss_date=entry.get('date'),
            )
        f['epss_status'] = 'available' if epss_fresh else 'stale' if has_data else 'unavailable'
        f['kev_evidence_status'] = 'available' if kev_fresh else 'stale' if isinstance(kev_data, dict) else 'unavailable'
        f['kev_status'] = ('listed' if cve in kev_data else 'not_listed') if kev_fresh else 'unavailable'
        f['threat_intelligence_retrieved_at'] = (entry.get('fetched_at') if has_data else None) or kev_time
    return rows
