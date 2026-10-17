# agent-decoy-secret-tripwire

**Agents leak secrets into logs, tool-call traces, and error messages — and nobody notices until the key is abused.**

Plant inert decoy credentials (honeytokens) where your agents operate, then scan logs for them. If a decoy shows up in a log file, a real secret would too — you've found the leak path before an attacker does.

## 30-second quickstart
```
mkdir -p plant && python agent_decoy_secret_tripwire.py plant --dir ./plant --label db
python agent_decoy_secret_tripwire.py scan --log-dir ./logs --plant-dir ./plant --json
```

## Example output
```
{
  "tripped": [
    {
      "label": "db",
      "file": "/tmp/tripwire2/logs/toolcalls.jsonl",
      "line": 1,
      "context": "{\"tool\":\"http\",\"args\":{\"key\":\"<decoy-token>\"}}"
    }
  ],
  "files_scanned": 1
}
```

`--kind openai-style | aws-style | generic`. Manifest stores only SHA-256 hashes, never the token itself.

## What it does NOT do
Decoys are inert (HONEYTOKEN-INERT infix, never valid credentials). A quiet scan means no decoy leaked — not proof your real secrets are safe.

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


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
