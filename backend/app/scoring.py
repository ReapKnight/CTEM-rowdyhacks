"""Versioned, explanatory hackathon prioritization. Not a calibrated risk model."""

from decimal import Decimal, ROUND_HALF_UP

MODEL_VERSION = "ctem-demo-v0.1"
CRITICALITY = {"low": 3, "medium": 7, "high": 11, "critical": 15}
SENSITIVITY = {"low": 1, "medium": 3, "high": 5}


def _rounded(value: float) -> float:
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def priority_for(finding: dict) -> dict:
    asset, threat, cvss = finding["asset"], finding["threat"], finding["cvss"]
    required = {
        "cvss.score": cvss["score"],
        "threat.epss_probability": threat["epss_probability"],
        "threat.kev": threat["kev"],
        "asset.internet_facing": asset["internet_facing"],
        "asset.data_sensitivity": asset["data_sensitivity"],
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        return {"score": None, "model_version": MODEL_VERSION, "categories": [], "missing_inputs": missing}

    epss, score = threat["epss_probability"], cvss["score"]
    if not 0 <= epss <= 1 or not 0 <= score <= 10:
        raise ValueError("EPSS probability or CVSS is out of range")
    production = asset["environment"] == "production"

    def category(key: str, maximum: int, factors: list[tuple[str, float, str]]) -> dict:
        explained = [{"label": name, "points": _rounded(points), "explanation": reason}
                     for name, points, reason in factors]
        return {"key": key, "max_points": maximum,
                "points": _rounded(sum(f["points"] for f in explained)), "factors": explained}

    categories = [
        category("threat", 30, [
            ("EPSS probability", 20 * epss, "20 × EPSS probability; EPSS is not asset compromise probability."),
            ("CISA KEV", 10 if threat["kev"] else 0, "10 points if listed in the retrieved KEV catalog."),
        ]),
        category("exposure", 25, [
            ("Predefined internet exposure", 25 if asset["internet_facing"] else 5,
             "Asset context supplied for the demo; the lab check does not establish internet exposure."),
        ]),
        category("business_impact", 25, [
            ("Criticality", CRITICALITY[asset["criticality"]], "Predefined business criticality."),
            ("Production environment", 5 if production else 0, "Production adds 5 points."),
            ("Data sensitivity", SENSITIVITY[asset["data_sensitivity"]], "Predefined data sensitivity."),
        ]),
        category("technical_severity", 20, [
            ("CVSS base score", 2 * score, "2 × supplied CVSS base score."),
        ]),
    ]
    return {"score": _rounded(sum(c["points"] for c in categories)),
            "model_version": MODEL_VERSION, "categories": categories, "missing_inputs": []}
