# Malware-Based ATM Cyber Heist: A Case Study of the Cosmos Bank Attack

**Course:** Cyber Security, CA2 (Case Study, Experiential Learning)
**Institute:** Symbiosis Institute of Technology, Pune (Department of Electronics & Telecommunication Engineering)
**Guide:** Dr Mangal Singh
**Group number:** G__ (fill in your B.Tech project group number)

| Member | PRN |
| --- | --- |
| Otniel Jhirad | 23070123069 |
| Athrav Shelar | 24070123501 |
| Dhanraj Chavan | 24070123502 |
| Kunal Ranjan | 24070123510 |

**GitHub link:** `<paste your repository link here>`

---

## 1. What this project is

This is a **qualitative case study** of the August 2018 Cosmos Bank cyberattack. The attackers compromised the bank's ATM payment switch (11 Aug 2018) and its SWIFT gateway (13 Aug 2018). Reported losses were about US$13.5 million: US$11.5 million through ATM withdrawals and US$2 million through SWIFT transfers.

The study uses **document analysis and threat modelling** (STRIDE, MITRE ATT&CK, MITRE D3FEND). It uses only published sources. It does **not** use the bank's internal logs, and it is not a forensic reconstruction.

## 2. What is in this zip

| File | Purpose |
| --- | --- |
| `README.md` | This file |
| `G__.pdf` | Final report (rename to your group number) |
| `source_review_matrix.xlsx` | Table 1 of the report: the source-review matrix (add this file) |
| `breach_detection_demo.py` | Small illustrative script for the algorithm in Section 5 |
| `Presentation/` | Video presentation and slides (if included) |

## 3. How to "run" the methodology

There is no software to install for the study itself. To follow or repeat the method, do these steps in order:

1. **Collect sources.** Pick published papers, advisories, incident reports and the bank's annual report. The report uses 30 references.
2. **Select by credibility.** Keep a document only if it is relevant, comes from a credible author or publisher, has identifiable publication details, and gives useful technical findings.
3. **Fill the source-review matrix.** For each source record: reference number, source type, key findings, theme, and limitation.
4. **Group findings into four themes:**
   - ATM switching infrastructure and unauthorized withdrawals
   - SWIFT-related fraudulent transactions
   - Attack characteristics and security weaknesses
   - Defensive measures
5. **Build the threat model:**
   1. Identify critical assets (ATM switch, CBS, SWIFT environment, transaction messages, logs).
   2. Classify threats with STRIDE.
   3. Use ATT&CK to interpret attacker behaviour, only where the evidence supports it.
   4. Assess risk and impact qualitatively.
   5. Map each threat to defences using D3FEND.
6. **Separate facts from interpretation.** Mark each claim as confirmed by the bank, proposed by Securonix, or only a potential scenario.
7. **Read the results** in Section 5 of the report (Tables 3 and 4).

## 4. Key findings (short)

- The incident hit **both** the ATM switch and the SWIFT system, so it was not only card fraud.
- Securonix proposes that a malicious component beside the ATM switch changed ISO 8583 responses, which let cloned non-EMV card withdrawals go through. The first entry point is still unconfirmed.
- Highest-priority risks: payment-switch manipulation and unauthorized SWIFT transfers.
- Layered security is needed across payment processing, with ATM, network, endpoint and SWIFT monitoring combined.

## 5. Algorithm to detect and respond to a breach like this

This is a **proposed defensive algorithm** built from the recommendations in Table 4 of the report. It is a design suggestion. It has not been tested on real bank data, and it does not prove the attack would have been stopped.

**Idea:** In this attack, the switch approved withdrawals that the core banking system (CBS) never approved. So the algorithm checks that every switch approval has a matching CBS approval, and it also watches the switch software, transaction patterns and SWIFT messages. If the checks agree that something is wrong, it starts the response.

### 5.1 Algorithm (pseudocode)

```
INPUT:  switch_log, cbs_log, running_hashes, approved_hashes,
        swift_messages, known_beneficiaries
OUTPUT: status (NORMAL / SUSPICIOUS / BREACH) and response actions

alerts = []

STEP 1  Integrity check (ATM switch)
    for each component in running_hashes:
        if hash(component) != approved_hashes[component]:
            add CRITICAL alert "unapproved or modified component"

STEP 2  Switch vs CBS reconciliation
    for each txn in switch_log where response == APPROVED:
        if cbs_log has no APPROVED record for txn.id:
            add CRITICAL alert "approval not backed by CBS"

STEP 3  Pattern / velocity check
    if withdrawals in a short time window > limit
       (or sudden spike in international / non-EMV transactions):
        add HIGH alert

STEP 4  SWIFT MT103 review
    for each message in swift_messages:
        if amount > limit OR beneficiary is new
           OR sent outside business hours OR only one approver:
            add HIGH alert

STEP 5  Correlate
    if any CRITICAL alert OR alerts come from 2 or more areas:
        status = BREACH
    else if alerts exist:
        status = SUSPICIOUS
    else:
        status = NORMAL

STEP 6  Respond (only if status == BREACH)
    CONTAIN   isolate ATM switch segment; block international / non-EMV txns
    CONTAIN   suspend outgoing SWIFT release; ask correspondent banks to hold
    PRESERVE  take forensic images; hash and lock logs (chain of custody)
    ERADICATE remove unapproved components; reset privileged credentials
    RECOVER   rebuild switch from trusted image; re-run reconciliation first
    REPORT    inform regulator / CERT-In as required; write lessons learned
```

### 5.2 Flowchart

```
   Collect logs, hashes, SWIFT messages
                 |
                 v
   1. Integrity check ----+
   2. Switch vs CBS ------+
   3. Velocity check -----+--> alerts list
   4. SWIFT review -------+
                 |
                 v
        5. Correlate alerts
          /        |        \
     NORMAL   SUSPICIOUS   BREACH
                 |            |
          investigate         v
                       6. Contain -> Preserve -> Eradicate
                          -> Recover -> Report
```

### 5.3 How each step links to the report

| Step | Threat from the report | Defence (Table 4) |
| --- | --- | --- |
| 1 | Payment-switch software manipulation | Integrity checks, process monitoring |
| 2 | Fabricated transaction responses | Reconcile switch messages with CBS records |
| 3 | Unauthorized access, mass withdrawals | Monitoring of transaction patterns |
| 4 | Suspicious SWIFT transfers | Monitor unusual MT103 amounts and beneficiaries |
| 6 | Evidence tampering, delayed response | Centralized logging, evidence preservation, incident response |

## 6. Optional: run the demo script

`breach_detection_demo.py` is a small Python version of Steps 1 to 6. It uses **synthetic data only**. It is not used to produce any finding in the report.

```
python breach_detection_demo.py
```

Requirements: Python 3.8 or higher. No extra packages are needed.

**Expected output:** Scenario A (normal activity) prints `NORMAL`. Scenario B (synthetic compromise) prints the alerts, then `BREACH DECLARED`, followed by the six response steps.

## 7. Limitations

- Only secondary, published sources are used. There is no access to Cosmos Bank logs, network captures or forensic images.
- The detail in public sources varies, and some attack details are unconfirmed.
- No numerical risk scores are calculated, because no suitable data is available.
- Techniques seen in other incidents (FASTCash, Bangladesh Bank, Taiwan First Bank) are used only as comparison, not as proof for Cosmos Bank.

## 8. Ethics

The study uses only published material. It involves no interviews, human participants or private banking records. It is for academic and defensive purposes only.

## 9. Main references

- [9] O. Kolesnikov and Securonix Threat Research Team, "Cosmos Bank SWIFT/ATM US$13.5 Million Cyber Attack Detection Using Security Analytics," 2018.
- [30] The Cosmos Co-operative Bank Ltd., 113th Annual Report 2018-2019.
- [6] CISA et al., "FASTCash 2.0: North Korea's BeagleBoyz Robbing Banks," AA20-239A, 2020.
- [25] K. F. Hasan et al., "ISADM: An Integrated STRIDE, ATT&CK, and D3FEND Model," IEEE Access, 2025.
- [28] R. Ross, NIST SP 800-30 Rev. 1, 2012.

The full list of 30 references is in the report PDF.
