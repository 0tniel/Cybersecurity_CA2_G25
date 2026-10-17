"""
Illustrative breach-detection prototype for the Cosmos Bank case study.

IMPORTANT: This script runs on SYNTHETIC data only. It is a demonstration of
the defensive algorithm described in README.md (Section 5). It is NOT used to
produce any finding in the report, and it does not reproduce the real attack.

Run:  python breach_detection_demo.py        (Python 3.8+, no extra packages)
"""
from collections import defaultdict

# ---------------- Tunable thresholds (example values) ----------------
VELOCITY_WINDOW_SEC = 60        # time window for burst detection
VELOCITY_MAX_TXNS = 5           # max withdrawals per window per switch
SWIFT_AMOUNT_LIMIT = 500_000    # review any MT103 above this amount
BUSINESS_HOURS = range(9, 18)   # normal hours for SWIFT release

# ---------------- Step 1: integrity check ----------------
def check_integrity(running_hashes, approved_hashes):
    """Alert on any process/library on the switch that is not whitelisted."""
    alerts = []
    for name, digest in running_hashes.items():
        if approved_hashes.get(name) != digest:
            alerts.append(("CRITICAL", "INTEGRITY",
                           f"Unapproved or modified component: {name}"))
    return alerts

# ---------------- Step 2: switch vs CBS reconciliation ----------------
def reconcile(switch_log, cbs_log):
    """A switch 'approve' must match an approval in the Core Banking System."""
    cbs = {t["txn_id"]: t["decision"] for t in cbs_log}
    bad = [t["txn_id"] for t in switch_log
           if t["response"] == "APPROVED" and cbs.get(t["txn_id"]) != "APPROVED"]
    if bad:
        return [("CRITICAL", "RECONCILIATION",
                 f"{len(bad)} txns approved by switch but not by CBS "
                 f"(first ids: {bad[:3]})")]
    return []

# ---------------- Step 3: velocity / pattern check ----------------
def check_velocity(switch_log):
    alerts, window = [], []
    for t in sorted(switch_log, key=lambda x: x["time"]):
        window = [w for w in window if t["time"] - w <= VELOCITY_WINDOW_SEC]
        window.append(t["time"])
        if len(window) > VELOCITY_MAX_TXNS:
            alerts.append(("HIGH", "VELOCITY",
                           f"{len(window)} withdrawals within "
                           f"{VELOCITY_WINDOW_SEC}s (at t={t['time']})"))
            break
    return alerts

# ---------------- Step 4: SWIFT MT103 review ----------------
def check_swift(messages, known_beneficiaries):
    alerts = []
    for m in messages:
        reasons = []
        if m["amount"] > SWIFT_AMOUNT_LIMIT:
            reasons.append("amount above limit")
        if m["beneficiary"] not in known_beneficiaries:
            reasons.append("new beneficiary")
        if m["hour"] not in BUSINESS_HOURS:
            reasons.append("outside business hours")
        if len(set(m["approvers"])) < 2:
            reasons.append("single approver")
        if reasons:
            alerts.append(("HIGH", "SWIFT",
                           f"MT103 {m['id']}: " + ", ".join(reasons)))
    return alerts

# ---------------- Step 5: correlate and decide ----------------
def correlate(alerts):
    domains = {a[1] for a in alerts}
    critical = any(a[0] == "CRITICAL" for a in alerts)
    if critical or len(domains) >= 2:
        return "BREACH DECLARED"
    return "SUSPICIOUS - INVESTIGATE" if alerts else "NORMAL"

RESPONSE_PLAYBOOK = [
    "1. CONTAIN: isolate the ATM switch segment; block international/non-EMV transactions",
    "2. CONTAIN: suspend outgoing SWIFT release; contact correspondent banks to hold/recall",
    "3. PRESERVE: take forensic images, hash and lock the logs (chain of custody)",
    "4. ERADICATE: remove unapproved components, reset privileged credentials",
    "5. RECOVER: restore switch from a trusted build, re-run reconciliation before go-live",
    "6. REPORT: notify regulator/CERT-In as required, then do a lessons-learned review",
]

def run(label, switch_log, cbs_log, swift_msgs, running_hashes):
    approved = {"switch_app": "a1", "iso8583_lib": "b2"}
    known = {"ACME TRADING LTD", "BETA SUPPLIES"}
    alerts = (check_integrity(running_hashes, approved)
              + reconcile(switch_log, cbs_log)
              + check_velocity(switch_log)
              + check_swift(swift_msgs, known))
    status = correlate(alerts)
    print(f"\n=== {label} ===")
    for sev, dom, msg in alerts:
        print(f"[{sev}] {dom}: {msg}")
    print("RESULT:", status)
    if status == "BREACH DECLARED":
        print("\n".join(RESPONSE_PLAYBOOK))

if __name__ == "__main__":
    # Scenario A: normal day
    sw = [{"txn_id": i, "response": "APPROVED", "time": i * 30} for i in range(3)]
    cb = [{"txn_id": i, "decision": "APPROVED"} for i in range(3)]
    sm = [{"id": "M1", "amount": 20_000, "beneficiary": "ACME TRADING LTD",
           "hour": 11, "approvers": ["u1", "u2"]}]
    run("Scenario A: normal activity", sw, cb, sm,
        {"switch_app": "a1", "iso8583_lib": "b2"})

    # Scenario B: synthetic compromise (fake approvals, unknown module, odd SWIFT)
    sw = [{"txn_id": i, "response": "APPROVED", "time": i} for i in range(20)]
    cb = []  # CBS never authorised these
    sm = [{"id": "M2", "amount": 900_000, "beneficiary": "UNKNOWN CO",
           "hour": 2, "approvers": ["u1"]}]
    run("Scenario B: synthetic compromise", sw, cb, sm,
        {"switch_app": "a1", "iso8583_lib": "b2", "mc_module": "zz"})
