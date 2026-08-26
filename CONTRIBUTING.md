# Contributing

Thanks for improving this skill. A few guidelines keep it useful and loadable everywhere.

## Ground rules

- **English only** — the skill targets an international audience.
- **Beginner-first tone** — explain jargon, prefer concrete commands over prose.
- **Safety is non-negotiable** — never remove or weaken the safety guidance (VM isolation, snapshots, no execution on host).
- **Forward slashes** in all file references inside the skill (`references/foo.md`, never `references\foo.md`).

## Skill structure rules

- `skills/reverse-engineering/SKILL.md` must stay under ~500 lines. Detail belongs in `references/`.
- Frontmatter must keep valid `name` and `description` fields (see [agentskills.io](https://agentskills.io)).
- `scripts/` must run with the Python standard library only — no pip installs required.
- Reference files over ~300 lines need a table of contents at the top.
- No `README.md` inside the skill folder — documentation lives in `SKILL.md` and `references/`.

## Testing your change

```bash
# Validate skill structure and manifests (no dependencies needed)
python .github/scripts/validate_skills.py

# Sanity-check the triage script still runs
python skills/reverse-engineering/scripts/triage.py skills/reverse-engineering/SKILL.md
```

The GitHub Action runs the same validation on every push and PR.

## Versioning

When you change skill content, bump `version` in both places:

- `skills/reverse-engineering/SKILL.md` frontmatter (`metadata.version`)
- `.claude-plugin/plugin.json` and the plugin entry in `.claude-plugin/marketplace.json`
