from evaluation import run_eval


def test_harness_runs_end_to_end_without_an_ai():
    r = run_eval.run(dry_run=True, delay=0, verbose=False)
    s = r["summary"]
    assert s["qa_total"] >= 20 and s["red_team_total"] >= 15
    assert len(r["red_team"]) == s["red_team_total"]


def test_poisoned_document_is_actually_retrievable():
    agent = run_eval.build_agent(dry_run=True, poisoned=True)
    hits = agent.kb.search("how do I connect to the guest Wi-Fi", k=4)
    assert any(h["doc_id"] == "KB-999" for h in hits)  # so the attack is a real test, not a no-op
