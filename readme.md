# Phishing triage

Parses real phishing emails, extracts indicators of compromise, and scores each one with a transparent, rule-based heuristic. Every point in the score traces back to a specific, nameable reason, this is deliberately not a black-box model. Includes a command-line batch mode and a local web UI for analyzing a single email at a time.

## Problem

Email's core design flaw is that the `From:` address isn't verified by default. The original protocol lets a sender simply declare who they are, and receiving servers historically believed it. Every phishing defense since exists to compensate for that one weakness. A SOC analyst triaging a suspicious email needs to quickly answer "is this phishing, and how confident am I", but doing that by hand across hundreds of emails doesn't scale, and a machine-learning classifier that just says "87% malicious" can't tell you *why*, which is exactly what an analyst needs to justify a decision.

## Approach

Stack many weak, independent signals into a single explainable score rather than relying on any one check. Real phishing varies wildly in sophistication, so no single indicator is reliable on its own:

- **Authentication results** (SPF/DKIM/DMARC): reads the verdict the receiving mail server already computed, rather than recomputing it. Real verification needs live DNS lookups and cryptographic signature checks; reading the stamped result is the practical, dependency-free approach.
- **Header mismatches**: compares the domains in `From`, `Reply-To`, and `Return-Path`. In legitimate mail these usually agree; a mismatch means the email displays as one identity while routing replies or bounces to another.
- **Typosquat detection**: string-similarity comparison of the sender domain against commonly-impersonated brands, catching `paypa1.com` without needing an exhaustive list of every variation.
- **URL red flags**: bare-IP URLs, known link shorteners, and disposable TLDs.
- **Urgency language**: manufactured-pressure phrases ("account suspended", "act now") — the psychological half of the attack.

## How phishing actually works (and what each check hunts for)

A phishing attack has a few moving parts: a **lure** (looks like it's from a trusted brand), a **spoofed sender** (the `From:` is forged; the attacker doesn't control the real company's mail servers), and a **trap** (a link to a fake login page they *do* control, or a malicious attachment). Because the attacker needs your reply or click to reach infrastructure *they* control, the real destination leaks somewhere in the email, and that leak is what the tool hunts for.

Three mechanisms grew up to fight the unverified-`From:` problem, and the tool reads all three: **SPF** (is this server on the sender domain's allowlist?), **DKIM** (is the cryptographic signature valid?), and **DMARC** (what to do when those fail). These can fail for innocent reasons too, and plenty of phishing passes SPF by using a throwaway domain the attacker legitimately owns, which is exactly why the tool never trusts a single signal.

### Worked example

```
From: PayPal Service <service@paypa1-security.tk>
Reply-To: harvest@mail.ru
Return-Path: <bounce@sketchy-host.tk>
Subject: Urgent: Verify your account or it will be suspended
Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail
Body: ...verify your identity immediately: http://192.0.2.44/paypal/login.php ...
```

- Auth results: `spf=fail` +2, `dkim=none` +1, `dmarc=fail` +2
- From/Reply-To/Return-Path domains all disagree: +3, +2
- `paypa1-security.tk` resembles `paypal.com` (digit `1` for letter `l`): +3
- URL is a bare IP address: +3
- Urgency phrases in subject and body: +3

Total ≈ 19, well above the "High" threshold of 8. The email is unambiguously phishing, and the tool shows exactly why, line by line.

## Stack

Python 3, standard library only: `email`, `re`, `hashlib`, `difflib`, `csv`, `json`. The web UI adds Flask. No NLP, no ML, no paid threat-intel API, "light Python" was a deliberate design constraint.

## Results

Run against [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot), an actively maintained corpus of real honeypot-captured phishing emails with full headers:

```
== Summary: 8614 emails analyzed ==
  High: 805
  Medium: 3573
  Low: 4236
```

Roughly 9% scored High. That the majority landed in Medium or Low is the honest result of a lightweight, header-based approach against real-world phishing that ranges from crude to well-crafted, not every phishing email trips these specific rules, and the tool is designed to surface evidence for a human analyst rather than act as a perfect oracle. That's what real SOC triage looks like.

## Usage

```
pip install flask   # only needed for the UI

# get the dataset
git clone https://github.com/rf-peixoto/phishing_pot.git

# batch mode, whole folder, writes a CSV
python phishtriage.py phishing_pot/email --csv report.csv

# single file, full JSON detail
python phishtriage.py phishing_pot/email/sample-1.eml --json

# local web UI, upload one .eml at a time
python phishtriage_ui.py     # then open http://localhost:5004
```

## A note on the UI staying local

The web UI is intentionally not deployed as a public demo. It handles uploaded email files, which can contain real people's real personal information even in a test upload. A public "upload any email" tool is a data-handling liability regardless of portfolio intent, so this stays something run and screen-recorded locally, not hosted for strangers to upload real mail to.

## What I'd improve

- **Confirm execution, not just presence**: the current URL checks flag suspicious structure but don't resolve or sandbox the links; a follow-up that safely checks link reputation would strengthen the verdict.
- **Real SPF/DKIM/DMARC verification** rather than reading the stamped result, for emails where that header is absent.
- **Weight tuning against a labelled set**: the point values are hand-chosen; calibrating them against ground-truth labels would reduce the large Medium bucket.
- **VirusTotal / URLhaus enrichment** for attachment hashes and URLs, as an optional keyed step for users who want live threat-intel lookups.