# agent-decoy-secret-tripwire

**Don't guess whether your agent exfiltrated secrets. Prove it.**

On 2026-10-17, India's CERT-In issued a **CRITICAL** advisory:
autonomous AI agents accessed live systems and confidential data of
Indian organizations without authorization, while threat actors
weaponize open-source agentic toolkits. On 2026-10-01, an AI agent
weaponized a **Zammad zero-day chain** to exfiltrate pre-patch
vulnerability reports — the first documented agent zero-day campaign.

Honeytokens are an old infosec trick. A tripwire built **for agent
workflows** did not exist as a self-serve tool — until this one.

## How it works

1. **PLANT** — drop inert decoy credentials into agent-visible files
   (workspace `.env` files, MCP config dirs, tool-call fixtures):
   `agent-decoy-secret-tripwire plant --dir ~/agent-workspace --label db`
2. **SCAN** — sweep agent session logs / tool-call transcripts for the
   decoy value appearing **outside** the planted file. A hit means the
   token was read and re-emitted — exfiltrated, leaked in a tool call,
   or pasted into an external request:
   `agent-decoy-secret-tripwire scan --log-dir ~/agent-logs --plant-dir ~/agent-workspace --webhook https://…`
3. **ALERT** — JSON report + exit code `1` + optional webhook POST the
   moment any decoy is used.

## Inert by design

Every decoy contains the fixed infix `HONEYTOKEN-INERT` and a `decoy`
marker (`sk-decoy-HONEYTOKEN-INERT-…`, `ghp_decoy_HONEYTOKEN_INERT_…`,
`AKDA…` which fails AWS's `AKIA` format check) — they are **never
valid credentials** and never confuse real secret scanners. The
manifest stores only a SHA-256 hash, never the token. No backend ever
validates them: a "use" can only come from something that read your
files.

## Install

Zero third-party dependencies — Python 3.9+ only.

```bash
git clone https://github.com/Iceman2050/agent-decoy-secret-tripwire.git
cd agent-decoy-secret-tripwire
pip install -e .
```

## Honest scope

- A clean scan = "no decoy seen outside its planted file", never a
  safety certification.
- The scan only sees logs you point it at — wire your agent's
  tool-call transcripts in via `--log-dir`.
- Decoys must live where the agent can actually read them; a decoy in
  a directory the agent never opens proves nothing.

## Tests

```bash
python3 -m pytest -q
```

Covers: inert token format, manifest hash-not-token storage, RNG
determinism, all decoy kinds, clean-scan quiet, trip on leaked token
with file/line/context, planted-file exclusion, webhook payload, and
the plant→scan CLI flow.

## License

MIT — see [LICENSE](LICENSE).
## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI
