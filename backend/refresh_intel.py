"""Refresh the small, dated EPSS/KEV snapshot for the prepared demo CVEs."""

import json
import math
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from .app.data import FIXTURES

EPSS_URL = "https://api.first.org/data/v1/epss?cve="
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
SNAPSHOT = Path(__file__).parent / "app" / "intel_snapshot.json"


def retrieve_json(url: str) -> dict:
    request = Request(url, headers={"User-Agent": "RowdyHacks-CTEM-intel-refresh/1.0"})
    with urlopen(request, timeout=25) as response:
        return json.load(response)


def build_snapshot(epss: dict, kev: dict, cves: list[str], retrieved_at: str) -> dict:
    if epss.get("status") != "OK" or not isinstance(epss.get("data"), list):
        raise ValueError("EPSS response is incomplete")
    rows = {row["cve"]: row for row in epss["data"]}
    if len(epss["data"]) != len(cves) or set(rows) != set(cves):
        raise ValueError("EPSS response does not cover exactly the requested CVEs")
    catalog = kev.get("vulnerabilities")
    if not isinstance(catalog, list) or not isinstance(kev.get("count"), int) or len(catalog) != kev["count"]:
        raise ValueError("KEV catalog is incomplete; membership cannot be trusted")
    kev_rows = {entry["cveID"]: entry for entry in catalog}
    if len(kev_rows) != len(catalog):
        raise ValueError("KEV catalog contains duplicate CVE IDs")
    entries = {}
    for cve in cves:
        row = rows[cve]
        probability, percentile = float(row["epss"]), float(row["percentile"])
        if not all(math.isfinite(x) and 0 <= x <= 1 for x in (probability, percentile)):
            raise ValueError(f"Invalid EPSS value for {cve}")
        date.fromisoformat(row["date"])
        match = kev_rows.get(cve)
        entries[cve] = {
            "cve_id": cve, "epss_probability": probability, "epss_percentile": percentile,
            "epss_date": row["date"], "kev": match is not None,
            "kev_date_added": match["dateAdded"] if match else None,
            "kev_retrieved_at": retrieved_at, "provenance": "verified_cached",
            "epss_source": EPSS_URL + cve, "kev_source": KEV_URL,
        }
    return {"schema_version": 2, "retrieved_at": retrieved_at,
            "kev_catalog_version": kev.get("catalogVersion"), "cves": entries}


def main() -> None:
    cves = sorted({finding["cve_id"] for finding in FIXTURES})
    epss = retrieve_json(EPSS_URL + ",".join(cves))
    kev = retrieve_json(KEV_URL)
    snapshot = build_snapshot(epss, kev, cves, datetime.now(timezone.utc).isoformat())
    temporary = SNAPSHOT.with_name(SNAPSHOT.name + ".tmp")
    temporary.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    temporary.replace(SNAPSHOT)
    print(f"Saved EPSS and full-catalog KEV data for {len(cves)} CVEs to {SNAPSHOT}")


if __name__ == "__main__":
    main()
