from evals.run import run_all


def test_eval_gate_passes():
    report = run_all()
    failed = [r for r in report["cases"] if r["status"] == "fail"]
    assert not failed, failed
    assert report["metrics"]["retrieval_mrr"] >= 0.75
    assert report["metrics"]["retrieval_hit3"] >= 0.85