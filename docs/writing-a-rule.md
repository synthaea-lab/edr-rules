# Writing a Sigma rule

This page walks through one rule from idea to pull request. The example detects `shred` wiping a
shell history file (ATT&CK T1070.003, Clear Command History). Every command and every error
message below was run against the current engines.

## 1. Check that the behaviour is visible to Sigma

The Sigma engine sees one process creation at a time: the image path, the command line and, when
the sensor provides it, the parent image. Before writing anything, check that the behaviour shows
up there:

- `shred -u ~/.bash_history` is a process with a recognisable image and argument. It is visible.
- `> ~/.bash_history`, `history -c` and `unset HISTFILE` are shell builtins or redirections. No
  process is created, so no Sigma rule can see them.

If the behaviour needs file, network, registry or sequence information, Sigma is the wrong layer;
it belongs in the agent's native rules or the correlator. The rule's description should say what is
out of scope, so that nobody mistakes the rule for full coverage of the technique.

## 2. Pick the directory

`shred` and shell history files exist on Linux and macOS, so the rule goes in `sigma/linux/`,
which macOS hosts also load. See
[which directory a host loads](layout-and-delivery.md#which-sigma-directory-a-host-loads).

## 3. Write the rule

`sigma/linux/shell_history_shredded.yml`:

```yaml
title: Shell history file shredded
description: >
  Detects shred overwriting a user's shell history file (.bash_history,
  .zsh_history), which destroys the record of the commands typed in that
  shell. Truncating the file with a redirection or unsetting HISTFILE is a
  shell builtin, not an exec, and is outside this rule.
tags:
  - attack.defense_evasion
  - attack.t1070.003
  - synthaea.coverage.defense_evasion
level: medium
falsepositives:
  - Privacy or hardening scripts that wipe shell history on logout or before
    an image is captured.
detection:
  selection:
    Image|endswith: '/shred'
    CommandLine|contains:
      - '.bash_history'
      - '.zsh_history'
  condition: selection
```

Choices worth noting:

- `Image|endswith: '/shred'` with the leading slash, so `/usr/bin/myshred` does not match.
- The `falsepositives` entry names a real benign cause. "None" is acceptable only with a reason.
- One ATT&CK technique tag is the minimum; the tactic and coverage tags follow the
  [tag conventions](sigma-rules.md#tags).

## 4. Write the samples

`sigma/linux/shell_history_shredded.samples.json`:

```json
{
  "matching": {
    "image": "/usr/bin/shred",
    "cmdline": "shred -u -z /home/alice/.bash_history"
  },
  "non_matching": {
    "image": "/usr/bin/shred",
    "cmdline": "shred -u /home/alice/old_disk.img",
    "note": "shred on a file that is not a shell history: the target file, not the tool, is the boundary."
  }
}
```

The near miss keeps the same binary and changes only the argument the rule depends on. If someone
later drops the `CommandLine` condition, this sample fires and the suite fails. See
[choosing a near miss](samples.md#choosing-a-near-miss).

## 5. Run the content suites

With the agent repository cloned next to this one (see [Testing and validation](testing.md)):

```sh
cd ../agent
cargo test -p sigma --test content --test platform
```

```text
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The suite names the file and the reason when something is wrong. These are the messages for the
common mistakes, trimmed of the absolute path:

| Mistake | Failing test and message |
| --- | --- |
| an unsupported modifier (`CommandLine\|re:`) | `every_shipped_rule_loads`: ``shipped rule failed to load: unsupported Sigma construct in .../shell_history_shredded.yml: modifier `re` (supported: contains, startswith, endswith, all)`` |
| no `falsepositives` | `every_shipped_rule_loads`: ``missing or invalid rule metadata in ...: missing `falsepositives` (must list at least one known FP scenario, or explain why none are known)`` |
| no samples file | `every_shipped_rule_has_exactly_its_samples_file`: ``.../shell_history_shredded.yml: no samples file; add .../shell_history_shredded.samples.json with a `matching` and a `non_matching` event`` |
| a near miss that matches | `every_shipped_rule_ignores_its_negative_sample`: ``benign lookalike for `Shell history file shredded` (.../shell_history_shredded.samples.json) fired: ["Shell history file shredded"]`` |

When a rule fails to load, the two sample tests fail as well, because they load every rule first.
Fix the load error and rerun.

## 6. Try it on a lab host (optional)

Copy the rule into a lab agent's content directory and reload, or run the agent against a checkout
(see [getting content onto a host](layout-and-delivery.md#getting-content-onto-a-host)). Then run
the matching command on the lab machine and look for the rule's title in the agent's alert log.
Do this on a disposable machine: the matching command really destroys the file.

## 7. Open the pull request

- Commit both files with a sign-off: `git commit -s`.
- In the description, state what the rule detects, the technique, the false positives you expect,
  and that the content suites pass.
- One rule, or one closely related group, per pull request.

## 8. Keep the agent's coverage page in step

The agent repository publishes a generated ATT&CK coverage page,
[`docs/attack-coverage.md`](https://github.com/synthaea-lab/agent/blob/main/docs/attack-coverage.md),
built from the agent's native rules and from this repository. The agent's checks (its CI workflow
and `tools/gauntlet.sh`) verify that the page is up to date against this repository's `main`, so any new, removed or retagged rule makes it stale once
merged. Regenerate it in the agent repository, with this checkout as the `rules` sibling:

```sh
cd ../agent
python3 tools/attack-coverage.py           # rewrite docs/attack-coverage.md
python3 tools/attack-coverage.py --check   # what the agent's CI runs
```

and open the agent pull request alongside this one. A technique the generator has no tactic for
appears under an "Unmapped" heading; add it to `TECHNIQUE_TACTIC` in
[`tools/attack-coverage.py`](https://github.com/synthaea-lab/agent/blob/main/tools/attack-coverage.py)
in the same pull request.

## Starting from a hunt

A self-hosted server can draft a rule from a saved hunt: `POST /api/hunts/<id>/graduate` with
`{"platform": "linux"}` returns the two files, laid out as `rules/sigma/<platform>/<slug>.yml` and
`.samples.json` (the content-directory layout; in this repository that is `sigma/<platform>/`),
plus a `todo` list. The draft is checked the way the engine will check it, but it is a starting
point: its `falsepositives` is a placeholder, the tactic and coverage tags are left to the author,
and a derived negative sample should be replaced with a real near miss. The code is
[`lib/hunt-graduation.ts`](https://github.com/synthaea-lab/server/blob/main/lib/hunt-graduation.ts)
in the server repository. `{"kind": "ioc"}` drafts an IOC feed instead, as `rules/ioc/<slug>.txt`.

## Adding a YARA rule instead

The steps differ in two places: the rule needs the three `meta:` keys described in
[YARA rule format](yara-rules.md#required-metadata), and its samples go in the agent repository,
not here. Write the rule, then add one matching and one non-matching entry for its identifier to
both tables in the agent's
[`crates/yara/tests/content.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/yara/tests/content.rs),
and run:

```sh
cd ../agent
cargo test -p yara --test content
```
