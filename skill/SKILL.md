---
name: malware-triage
description: >
  Perform initial static triage of a PE malware sample (Windows .exe or .dll).
  Use this skill whenever a user asks to analyze, triage, inspect, or report on
  a suspicious binary, malware sample, or PE file — even if they don't use the
  word "triage". Triggers include: "analyze this binary", "check this exe",
  "what does this dll do", "malware analysis", "suspicious file", "run floss",
  "check imports", "look up on VirusTotal". Never execute the sample; all
  analysis is strictly static and read-only.
allowed-tools: Read, Write
---

# Malware Initial Triage Skill

Produces a concise executive summary from a pre-generated static-analysis
report.  The full 8-step analysis pipeline (hashes, VirusTotal, entropy,
imports, exports, FLOSS strings, report assembly) is run externally by
`malware_watcher.py` inside a Docker container before this skill is invoked.
The sample is **never executed**.

---

## Safety Rules (Non-Negotiable)

1. **Never execute the sample** — not directly, not via shell, not via Python `subprocess`, not via any interpreter.
2. All analysis is read-only; the sample file is not touched.

---

## Workflow

Given a path to a completed `*_triage.md` report and a destination path for
the summary:

1. **Read** the triage report.
2. **Write** a concise executive summary (max ~300 words) to the destination path.

The summary must include:
- File hashes (MD5, SHA-1, SHA-256)
- VirusTotal verdict (detection ratio, threat label)
- Key suspicious imports (function name + category)
- Notable IoCs (network indicators, file paths, registry keys)
- Overall risk assessment: **Low / Medium / High / Critical**

---

## Report Structure (reference)

The `*_triage.md` report passed to this skill contains three sections:

### File Meta-Data
- Hashes (MD5, SHA-1, SHA-256), file size
- Architecture, image base, entry point RVA
- VirusTotal result (detection ratio, threat label, first seen)
- PE section table with entropy values; sections ≥ 6.5 flagged

### Imports / Exports
- **Suspicious imports** table — DLL, function name, category (from `references/suspicious_imports.md`)
- **All imported DLLs** summary (name + import count)
- **Exports & TLS Callbacks** table (RVA + symbol name)

### Relevant IoCs
- Strings from FLOSS filtered to length ≥ 6 and entropy < 6.5
- Sub-categorized: **Network Indicators**, **File System Paths**, **Registry Keys**, **Other Strings**
