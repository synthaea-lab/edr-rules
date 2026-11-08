# rules — Detection Content

Detection content shipped to agents, kept separate from engine code so it can ship on its
own cadence (canary rings). To be migrated/curated from `old/rules` after review.

Part of Synthaea, alongside the public synthaea-lab/agent, synthaea-lab/server and
synthaea-lab/ml repositories. The engines that validate this content live in
synthaea-lab/agent. To run the content suites, check it out next to this repo as `agent/`
(this one as `rules/`, or point `SYNTHAEA_ROOT` at their parent) and, from `agent/`:

```sh
cargo test -p sigma --test content
cargo test -p yara --test content
cargo test -p intel --test content
```

Each suite loads this whole tree through the real engine: every rule must compile and fire
on its crafted matching sample. `SYNTHAEA_REQUIRE_SIBLINGS=1` makes a missing `rules/`
checkout fail instead of skipping. CI does the same: `.github/workflows/content.yml`.

| Path | Purpose |
| --- | --- |
| `sigma/` | Sigma rules — behavioral detections on the event stream, organized by platform and ATT&CK technique |
| `yara/` | YARA rules — file and memory content scanning, organized by category |
| `ioc/` | IOC feeds (proposed, #934) — one `<feed>.txt` per file, `sha256:` / `ip:` / `domain:` lines (ADR-0038); CI loads each through the engine and the server's feed builder |
