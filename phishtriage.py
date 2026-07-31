#!/usr/bin/env python3
"""
phishtriage - parses real phishing emails, extracts IOCs, and scores
them with a transparent, rule-based heuristic. Every point in the
score is explainable, this is deliberately not a black-box ML model.

"Light Python" by design: stdlib's own email module does the actual
parsing. Enrichment stays local and keyless, no paid threat-intel API,
based on signals already present in the email itself: authentication
results the receiving server already computed, header mismatches, and
simple structural red flags in URLs, rather than live reputation
lookups against a third-party service.

Dataset this was built against: rf-peixoto/phishing_pot, an actively
maintained, honeypot-captured real phishing corpus with full headers.
    git clone https://github.com/rf-peixoto/phishing_pot.git

Usage:
    python phishtriage.py ./phishing_pot/email --csv report.csv
    python phishtriage.py ./phishing_pot/email/sample-1.eml --json
"""

import argparse
import csv
import difflib
import hashlib
import json
import os
import re
import sys
from email import policy
from email.parser import BytesParser

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
KNOWN_BRANDS = [
    "paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com",
    "bankofamerica.com", "chase.com", "netflix.com", "facebook.com", "linkedin.com",
]
URGENCY_KEYWORDS = [
    "urgent", "verify your account", "account suspended", "act now",
    "confirm your identity", "unusual activity", "click here immediately",
    "your account will be closed", "immediate action required", "password expires",
]


def parse_eml(path: str):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_body_text(msg) -> str:
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(str(part.get_content()))
                except Exception:
                    pass
    else:
        try:
            parts.append(str(msg.get_content()))
        except Exception:
            pass
    return "\n".join(parts)


def extract_headers(msg) -> dict:
    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "received": msg.get_all("Received", []) or [],
        "auth_results": msg.get_all("Authentication-Results", []) or [],
    }


def extract_iocs(msg, body_text: str) -> dict:
    urls = sorted(set(URL_PATTERN.findall(body_text)))
    ips = sorted(set(IP_PATTERN.findall(body_text)))

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True) or b""
                sha256 = hashlib.sha256(payload).hexdigest()
                attachments.append({"filename": filename, "sha256": sha256, "size": len(payload)})

    return {"urls": urls, "ips": ips, "attachments": attachments}


def extract_domain(addr: str) -> str:
    match = re.search(r"@([\w.-]+)", addr or "")
    return match.group(1).lower() if match else ""


def check_auth_results(auth_headers: list) -> list:
    """
    Parses what the receiving mail server already computed, doesn't
    perform SPF/DKIM/DMARC verification itself. That verification is
    genuinely complex (DNS lookups, cryptographic signature checks);
    reading the already-computed result is the practical, light-Python
    approach here.
    """
    findings = []
    combined = " ".join(auth_headers).lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", combined)
        if match and match.group(1) in ("fail", "softfail", "none"):
            weight = 2 if match.group(1) == "fail" else 1
            findings.append({"signal": f"{mechanism}_{match.group(1)}", "weight": weight})
    return findings


def check_from_reply_mismatch(headers: dict) -> list:
    from_domain = extract_domain(headers["from"])
    reply_domain = extract_domain(headers["reply_to"])
    return_domain = extract_domain(headers["return_path"])

    findings = []
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append({"signal": f"reply_to_mismatch ({from_domain} vs {reply_domain})", "weight": 3})
    if return_domain and from_domain and return_domain != from_domain:
        findings.append({"signal": f"return_path_mismatch ({from_domain} vs {return_domain})", "weight": 2})
    return findings


def check_typosquat(from_domain: str) -> list:
    if not from_domain:
        return []
    for brand in KNOWN_BRANDS:
        if from_domain == brand:
            continue
        similarity = difflib.SequenceMatcher(None, from_domain, brand).ratio()
        if 0.75 <= similarity < 1.0:
            return [{"signal": f"possible_typosquat ({from_domain} ~ {brand}, {similarity:.2f})", "weight": 3}]
    return []


def check_url_patterns(urls: list) -> list:
    findings = []
    for url in urls:
        host_match = re.search(r"https?://([^/]+)", url)
        if not host_match:
            continue
        host = host_match.group(1).lower()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append({"signal": f"ip_based_url ({url[:60]})", "weight": 3})
        if any(host.endswith(short) for short in SHORTENERS):
            findings.append({"signal": f"url_shortener ({url[:60]})", "weight": 1})
        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append({"signal": f"suspicious_tld ({url[:60]})", "weight": 2})
    return findings


def check_urgency_language(subject: str, body: str) -> list:
    text = f"{subject} {body}".lower()
    return [{"signal": f"urgency_phrase ('{phrase}')", "weight": 1} for phrase in URGENCY_KEYWORDS if phrase in text]


def score_email(path: str) -> dict:
    msg = parse_eml(path)
    headers = extract_headers(msg)
    body_text = get_body_text(msg)
    iocs = extract_iocs(msg, body_text)
    from_domain = extract_domain(headers["from"])

    findings = []
    findings += check_auth_results(headers["auth_results"])
    findings += check_from_reply_mismatch(headers)
    findings += check_typosquat(from_domain)
    findings += check_url_patterns(iocs["urls"])
    findings += check_urgency_language(headers["subject"], body_text)

    score = sum(f["weight"] for f in findings)
    verdict = "High" if score >= 8 else "Medium" if score >= 4 else "Low"

    return {
        "file": os.path.basename(path),
        "from": headers["from"],
        "subject": headers["subject"],
        "score": score,
        "verdict": verdict,
        "findings": [f["signal"] for f in findings],
        "urls": iocs["urls"],
        "ips": iocs["ips"],
        "attachments": [a["filename"] for a in iocs["attachments"]],
    }


def main():
    parser = argparse.ArgumentParser(description="Phishing email header/IOC analyzer and scorer")
    parser.add_argument("path", help="a single .eml file, or a folder of them")
    parser.add_argument("--csv", help="write a CSV report to this path")
    parser.add_argument("--json", action="store_true", help="print full JSON instead of the summary table")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        files = [os.path.join(args.path, f) for f in sorted(os.listdir(args.path)) if f.lower().endswith(".eml")]
    else:
        files = [args.path]

    if not files:
        print(f"[!] No .eml files found in {args.path}", file=sys.stderr)
        sys.exit(1)

    results = []
    for f in files:
        try:
            results.append(score_email(f))
        except Exception as e:
            print(f"[!] Failed to parse {f}: {e}", file=sys.stderr)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'File':<20} {'Score':<7} {'Verdict':<8} Subject")
        for r in results:
            print(f"{r['file'][:19]:<20} {r['score']:<7} {r['verdict']:<8} {r['subject'][:55]}")

        verdict_counts = {}
        for r in results:
            verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1
        print(f"\n== Summary: {len(results)} emails analyzed ==")
        for v in ("High", "Medium", "Low"):
            print(f"  {v}: {verdict_counts.get(v, 0)}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["file", "from", "subject", "score", "verdict", "findings", "urls", "ips", "attachments"])
            for r in results:
                writer.writerow([
                    r["file"], r["from"], r["subject"], r["score"], r["verdict"],
                    "; ".join(r["findings"]), "; ".join(r["urls"]), "; ".join(r["ips"]), "; ".join(r["attachments"]),
                ])
        print(f"\n[*] CSV report written to {args.csv}")


if __name__ == "__main__":
    main()