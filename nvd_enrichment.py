"""Optional NVD CVE enrichment for VulnX, using only the Python standard library."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _first_description(cve_record):
    for item in cve_record.get("descriptions", []):
        if item.get("lang") == "en" and item.get("value"):
            return item["value"]
    return ""


def _best_cvss(metrics):
    # Prefer the newest CVSS version available, then fall back gracefully.
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        metric = entries[0]
        data = metric.get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or metric.get("baseSeverity") or ""
        if score is not None:
            return {"cvss_version": version, "cvss_score": score,
                    "cvss_severity": str(severity).upper(),
                    "cvss_vector": data.get("vectorString", "")}
    return {"cvss_version": "", "cvss_score": None, "cvss_severity": "", "cvss_vector": ""}


def parse_nvd_response(payload, requested_cve=""):
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {"cve": requested_cve, "status": "not_found", "description": "",
                "published": "", "last_modified": "", "references": [], **_best_cvss({})}
    item = vulnerabilities[0].get("cve") or {}
    cve_id = item.get("id") or requested_cve
    references = []
    for ref in item.get("references") or []:
        url = ref.get("url")
        if url and url not in references:
            references.append(url)
    return {"cve": cve_id, "status": "enriched", "description": _first_description(item),
            "published": item.get("published", ""), "last_modified": item.get("lastModified", ""),
            "references": references[:10], **_best_cvss(item.get("metrics") or {})}


def fetch_nvd_cve(cve_id, api_key=None, timeout=15):
    """Fetch one CVE; returns structured data or a non-throwing error status."""
    cve_id = str(cve_id or "").strip().upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        return {"cve": cve_id, "status": "skipped_non_cve", "error": "Identifier is not a valid CVE ID."}
    api_key = api_key or os.getenv("NVD_API_KEY")
    url = NVD_API_URL + "?" + urllib.parse.urlencode({"cveId": cve_id})
    headers = {"User-Agent": "VulnX/1.0 academic-vulnerability-management-project"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return parse_nvd_response(json.loads(response.read().decode("utf-8")), cve_id)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"cve": cve_id, "status": "not_found", "error": "CVE was not found in NVD."}
        if exc.code == 429:
            message = "NVD rate limit reached. Wait before retrying or configure an NVD API key."
        else:
            message = f"NVD returned HTTP {exc.code}."
        return {"cve": cve_id, "status": "error", "error": message}
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"cve": cve_id, "status": "error", "error": f"NVD lookup failed: {exc.__class__.__name__}. Check internet access and retry."}


def load_cache(cache_path):
    path = Path(cache_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_cache(cache_path, cache):
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False), encoding="utf-8")
    temp_path.replace(path)


def enrich_cve_batch(cve_ids, cache_path, api_key=None, limit=10, delay_seconds=6):
    """Enrich up to limit uncached CVEs per click to respect public API limits."""
    cache = load_cache(cache_path)
    unique_ids = list(dict.fromkeys(str(x).strip().upper() for x in cve_ids if CVE_ID_RE.fullmatch(str(x).strip().upper())))
    pending = [cve for cve in unique_ids if cve not in cache or cache[cve].get("status") == "error"]
    selected = pending[:max(1, int(limit))]
    results = []
    for index, cve in enumerate(selected):
        result = fetch_nvd_cve(cve, api_key=api_key)
        cache[cve] = result
        results.append(result)
        if result.get("status") == "error" and "rate limit" in str(result.get("error", "")).lower():
            break  # stop hammering NVD once it says 429; remaining CVEs stay pending
        if index < len(selected) - 1 and delay_seconds > 0:
            time.sleep(delay_seconds)
    save_cache(cache_path, cache)
    return cache, results, len(pending) - len(results)
