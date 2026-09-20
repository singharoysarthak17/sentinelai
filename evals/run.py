import json
from collections import Counter
from pathlib import Path

from evals.cases import CASES, Result

REPORT = Path(__file__).resolve().parent / "report.json"
MIN_MRR, MIN_HIT3 = 0.75, 0.85


def _status(case, r: Result) -> str:
    if r.metrics.get("skipped"):
        return "skipped"
    if r.passed:
        return "pass"
    if case.area == "retrieval":
        return "miss"
    return "fail" if case.gating else "known_gap"


def run_all() -> dict:
    rows, rr, e2e = [], [], {}
    for c in CASES:
        try:
            r = c.run()
        except Exception as e:  # a crashing case is a failure, not a crash of the suite
            r = Result(False, f"crashed: {type(e).__name__}: {e}")
        if c.area == "retrieval":
            rr.append(r.metrics.get("rr", 0.0))
        if c.area == "e2e":
            e2e = {k: v for k, v in r.metrics.items() if k != "skipped"}
        rows.append({"id": c.id, "area": c.area, "title": c.title,
                     "status": _status(c, r), "detail": r.detail, "origin": c.origin})

    n = len(rr)
    hits = sum(1 for row in rows if row["area"] == "retrieval" and row["status"] == "pass")
    metrics = {"retrieval_mrr": round(sum(rr) / n, 3) if n else 0.0,
               "retrieval_hit3": round(hits / n, 3) if n else 0.0, "e2e": e2e}
    failed = [r for r in rows if r["status"] == "fail"]
    gate = (not failed and metrics["retrieval_mrr"] >= MIN_MRR
            and metrics["retrieval_hit3"] >= MIN_HIT3)
    report = {"gate": "PASS" if gate else "FAIL", "metrics": metrics, "cases": rows}
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def show(report: dict) -> None:
    areas: dict[str, Counter] = {}
    for row in report["cases"]:
        areas.setdefault(row["area"], Counter())[row["status"]] += 1
    print(f"{'AREA':<11}{'pass':>5}{'fail':>6}{'miss':>6}{'gap':>5}{'skip':>6}")
    for area, c in areas.items():
        print(f"{area:<11}{c['pass']:>5}{c['fail']:>6}{c['miss']:>6}"
              f"{c['known_gap']:>5}{c['skipped']:>6}")
    m = report["metrics"]
    print(f"\nRetrieval: MRR {m['retrieval_mrr']}, hit@3 {m['retrieval_hit3']}")
    if m["e2e"]:
        print("End-to-end run:", m["e2e"])
    print()
    for row in report["cases"]:
        if row["status"] in ("fail", "miss", "known_gap", "skipped"):
            note = f"  [{row['origin']}]" if row["origin"] else ""
            print(f"  {row['status'].upper():<9} {row['id']}: {row['title']} -> {row['detail']}{note}")
    print("\nGATE:", report["gate"])


if __name__ == "__main__":
    rep = run_all()
    show(rep)
    raise SystemExit(0 if rep["gate"] == "PASS" else 1)