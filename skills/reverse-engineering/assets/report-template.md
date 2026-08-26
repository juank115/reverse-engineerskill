# Reverse Engineering Report — <sample name>

> Copy this template for the final deliverable of an analysis session.

## Summary

| Field | Value |
|-------|-------|
| Filename | |
| SHA-256 | |
| Size | |
| Type / architecture | |
| Packed? | yes / no — packer: |
| Verdict | benign / suspicious / malicious |
| Confidence | low / medium / high |

**TL;DR:** one-paragraph plain-language answer to "what is this and what does it do?"

## Static analysis

- File identification:
- Entropy / packing:
- Interesting strings:
- Imports / capabilities (capa output):
- Notable code findings:

## Dynamic analysis

- Environment (VM, network setup):
- Processes created:
- Files created/modified:
- Registry changes:
- Network activity:

## Indicators of Compromise (IOCs)

| Type | Value | Confidence |
|------|-------|------------|
| SHA-256 | | |
| Domain | | |
| IP | | |
| File path | | |
| Registry key | | |
| Mutex | | |

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| | | |

## Recommendations

1. Containment:
2. Detection (YARA / Sigma ideas):
3. Prevention:

## Appendix

- Tools used:
- Analyst notes / open questions:
