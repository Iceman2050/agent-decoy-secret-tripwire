"""agent-decoy-secret-tripwire: prove a rogue agent touched your secrets.

On 2026-10-17, India's CERT-In issued a CRITICAL advisory: autonomous
AI agents accessed live systems and confidential data of Indian
organizations without authorization, while threat actors weaponize
open-source agentic toolkits. On 2026-10-01, an AI agent weaponized a
Zammad zero-day chain to exfiltrate pre-patch vulnerability reports —
the first documented agent zero-day campaign.

Honeytokens are an old infosec trick; a tripwire built FOR agent
workflows did not exist as a self-serve tool — until this one.

How it works:
  1. PLANT: drop inert decoy credentials into agent-visible files
     (workspace .env files, MCP config dirs, tool-call fixtures).
     Every decoy contains the fixed infix ``HONEYTOKEN-INERT`` so it
     is NEVER a valid credential and NEVER confuses real secret
     scanners (documented, greppable).
  2. SCAN: sweep agent session logs / tool-call transcripts for the
     decoy value appearing OUTSIDE the planted file. A hit means the
     token was read and re-emitted — exfiltrated, leaked in a tool
     call, or pasted into an external request.
  3. ALERT: JSON report + non-zero exit + optional webhook POST.

Inert by design: decoys look like keys (``sk-decoy-HONEYTOKEN-INERT-…``,
``ghp_decoy_HONEYTOKEN_INERT_…``) but fail every real provider's key
format check, and no backend ever validates them — a "use" can only
come from something that READ your files. A clean scan is "no decoy
seen outside its planted file", never a safety certification.
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import urllib.request

INFIX = "HONEYTOKEN-INERT"
MANIFEST_NAME = ".decoy-manifest.json"
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

DECOY_KINDS = (
    ("openai-style", "sk-decoy-{infix}-{rand}"),
    ("github-style", "ghp_decoy_{infix}_{rand}"),
    ("aws-style", "AKDA{rand16}"),  # AKDA ≠ AKIA: fails AWS format check
    ("slack-style", "xoxb-decoy-{infix}-{rand}"),
)


def _rand(n, rng):
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def plant(directory, label, kind="openai-style", rng=None):
    """Plant one decoy file; return (path, token).

    The decoy file is written INSIDE directory as .env.decoy-<label>.
    """
    rng = rng or random.Random()
    template = dict(DECOY_KINDS).get(kind, DECOY_KINDS[0][1])
    token = template.format(infix=INFIX, rand=_rand(24, rng),
                            rand16=_rand(16, rng))
    path = os.path.join(directory, ".env.decoy-%s" % label)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# agent-visible decoy credential (INERT — do not use)\n"
                 "DECOY_API_KEY=%s\n" % token)
    manifest_path = os.path.join(directory, MANIFEST_NAME)
    manifest = {}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                manifest = json.load(fh)
        except (OSError, ValueError):
            manifest = {}
    manifest[label] = {
        "kind": kind,
        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
        "planted_file": os.path.basename(path),
        "infix": INFIX,
    }
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return path, token


def load_manifest(directory):
    path = os.path.join(directory, MANIFEST_NAME)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def scan(log_dir, plant_dir, extensions=(".log", ".json", ".jsonl",
                                        ".txt", ".md")):
    """Scan log_dir for decoy tokens outside their planted files.

    Returns {"tripped": [...], "files_scanned": n}. Each trip:
    {"label", "file", "line", "context"}.
    """
    manifest = load_manifest(plant_dir)
    tokens = {}
    for label, meta in manifest.items():
        planted = os.path.join(plant_dir, meta.get("planted_file", ""))
        try:
            with open(planted, "r", encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    if line.startswith("DECOY_API_KEY="):
                        tokens[label] = line.split("=", 1)[1].strip()
        except OSError:
            continue
    trips = []
    files_scanned = 0
    planted_names = {os.path.join(plant_dir, m.get("planted_file", ""))
                     for m in manifest.values()}
    for root, _, files in os.walk(log_dir):
        for fn in files:
            if not fn.endswith(extensions):
                continue
            path = os.path.join(root, fn)
            if path in planted_names:
                continue
            files_scanned += 1
            try:
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for label, token in tokens.items():
                            if token and token in line:
                                trips.append({
                                    "label": label, "file": path,
                                    "line": lineno,
                                    "context": line.strip()[:160],
                                })
            except OSError:
                pass
    return {"tripped": trips, "files_scanned": files_scanned}


def webhook_payload(trips):
    return {"event": "decoy-secret-tripwire",
            "trips": trips,
            "summary": "%d decoy credential(s) observed outside planted "
                       "files" % len(trips)}


def post_webhook(url, payload, timeout=10):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def render_markdown(report):
    trips = report["tripped"]
    lines = ["# Decoy Secret Tripwire", "",
             "- Log files scanned: %d" % report["files_scanned"],
             "- Trips: %d" % len(trips), ""]
    if trips:
        lines.append("## 🚨 TRIPPED — decoy credential seen outside its "
                     "planted file")
        for t in trips:
            lines.append("- decoy `%s` in `%s` line %d" %
                         (t["label"], t["file"], t["line"]))
            lines.append("  - context: `%s`" % t["context"])
        lines.append("")
        lines.append("A planted honeytoken was read and re-emitted. Treat "
                     "as unauthorized agent exfiltration until proven "
                     "otherwise.")
    else:
        lines.append("No decoy observed outside its planted file — the "
                     "tripwire is armed and quiet.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Plant inert decoy credentials and alert on first use.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plant", help="plant a decoy in a directory")
    p.add_argument("--dir", required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--kind", default="openai-style",
                   choices=[k for k, _ in DECOY_KINDS])
    s = sub.add_parser("scan", help="scan logs for decoy usage")
    s.add_argument("--log-dir", required=True)
    s.add_argument("--plant-dir", required=True)
    s.add_argument("--webhook", default="")
    s.add_argument("--json", dest="as_json", action="store_true")
    s.add_argument("--out", default="-")
    args = ap.parse_args(argv)
    if args.cmd == "plant":
        path, token = plant(args.dir, args.label, kind=args.kind)
        sys.stdout.write("planted %s (%s)\n" % (path, token[:20] + "…"))
        return 0
    report = scan(args.log_dir, args.plant_dir)
    if args.webhook and report["tripped"]:
        try:
            post_webhook(args.webhook, webhook_payload(report["tripped"]))
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("webhook failed: %r\n" % exc)
    out = json.dumps(report, indent=2) if args.as_json \
        else render_markdown(report)
    if args.out == "-":
        sys.stdout.write(out)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    return 1 if report["tripped"] else 0


if __name__ == "__main__":
    sys.exit(main())
