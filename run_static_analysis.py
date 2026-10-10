"""Runs Bandit (Python security linter) on both versions and stores the reports in results/."""
import json, subprocess, sys, os
os.makedirs("results", exist_ok=True)
summary = {}
for kind, path in (("vulnerable", "vulnerable/app_vulnerable.py"), ("secure", "secure/app_secure.py")):
    p = subprocess.run([sys.executable, "-m", "bandit", "-f", "json", "-q", path], capture_output=True, text=True)
    data = json.loads(p.stdout)
    open("results/bandit_%s.json" % kind, "w").write(json.dumps(data, indent=2))
    sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in data["results"]:
        sev[r["issue_severity"]] += 1
    summary[kind] = {"total": len(data["results"]), **sev,
                     "issues": [{"id": r["test_id"], "sev": r["issue_severity"], "line": r["line_number"],
                                 "text": r["issue_text"]} for r in data["results"]],
                     "suppressed_nosec": data["metrics"]["_totals"].get("nosec", 0)}
    print("%-10s total=%d  HIGH=%d MEDIUM=%d LOW=%d" % (kind, len(data["results"]), sev["HIGH"], sev["MEDIUM"], sev["LOW"]))
json.dump(summary, open("results/bandit_summary.json", "w"), indent=2)
