# Testing and validation

This repository has no test code of its own. Its content is validated by suites in the
[agent repository](https://github.com/synthaea-lab/agent) that load this tree with the engines the
agent runs. The design keeps one definition of "valid": if the suite accepts a rule, a host loads
it, and if the engine changes what it accepts, the suite sees it on the next run.

## Local setup

Clone both repositories side by side, with the default directory names:

```sh
git clone https://github.com/synthaea-lab/rules
git clone https://github.com/synthaea-lab/agent
cd agent
```

Then, from `agent/`:

```sh
cargo test -p sigma --test content --test platform   # Sigma rules and samples
cargo test -p yara --test content                    # YARA rules
cargo test -p intel --test content                   # IOC feeds under ioc/
```

- The Rust toolchain is pinned in the agent's
  [`rust-toolchain.toml`](https://github.com/synthaea-lab/agent/blob/main/rust-toolchain.toml);
  `rustup` installs it on first use. The first build compiles YARA-X and its WebAssembly runtime
  and takes several minutes and a few GiB of disk.
- On Linux, the agent's [`.cargo/config.toml`](https://github.com/synthaea-lab/agent/blob/main/.cargo/config.toml)
  runs every test binary through `sudo -E`, for the eBPF tests. The content suites do not need
  root. To run them without a password prompt, override the runner for your target:

  ```sh
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=env cargo test -p sigma --test content --test platform
  ```

### Finding the sibling checkout

The suites locate this repository through the agent's
[`siblings`](https://github.com/synthaea-lab/agent/blob/main/crates/siblings/src/lib.rs) test crate:

| Variable | Effect |
| --- | --- |
| `SYNTHAEA_ROOT` | The directory that holds the `rules` checkout. Default: the parent directory of the agent checkout. |
| `SYNTHAEA_REQUIRE_SIBLINGS=1` | A missing `rules` checkout fails the test instead of skipping it. |

Without the sibling, each content test prints a `skipped: ...` line and passes. `cargo test` hides
that line on success, so a run that found nothing looks green. Set `SYNTHAEA_REQUIRE_SIBLINGS=1`
whenever the result matters:

```sh
SYNTHAEA_REQUIRE_SIBLINGS=1 cargo test -p sigma --test content --test platform
```

To test a working copy kept somewhere else, point `SYNTHAEA_ROOT` at a directory containing it
under the name `rules`.

## What the suites assert

### Sigma: `crates/sigma/tests/content.rs`

[Source](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/content.rs).

| Test | Fails when |
| --- | --- |
| `every_shipped_rule_loads` | any rule fails to parse or validate (loaded one by one, so a skip becomes a failure naming the file), or the engine loads fewer rules than there are files |
| `every_shipped_rule_has_exactly_its_samples_file` | a rule has no samples file, or a samples file has no rule |
| `every_shipped_rule_fires_on_its_sample` | a rule's title is not among the hits for its `matching` event |
| `every_shipped_rule_ignores_its_negative_sample` | any rule fires on a `non_matching` event |
| `the_storage_and_paste_rules_cover_each_listed_domain_and_upload_shape` | the curl upload rules miss a listed host or upload flag, or fire across the storage/paste split |
| `the_local_and_remote_shell_service_rules_split_on_the_unc_argument` | the local and remote `sc.exe` service rules stop splitting on a `\\host` argument |
| `the_web_server_lineage_rules_cover_every_listed_parent_and_interpreter` and `..._ignore_lookalikes_and_a_missing_lineage` | the Windows and macOS web-server lineage rules miss a listed pair or fire on a lookalike or without lineage |

The remaining tests in the file check the suite's own pairing and samples parsing with temporary
files.

### Sigma platform split: `crates/sigma/tests/platform.rs`

[Source](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/platform.rs). Most
tests build a temporary tree. Three read this repository:

| Test | Fails when |
| --- | --- |
| `the_shipped_content_splits_as_the_expected_set_says` | a platform directory is empty, a host loads a different number of rules than the `.yml` files it should, or a rule title appears on both Windows and a Unix-family host |
| `a_linux_rule_runs_on_macos_and_not_on_windows` | the reverse-shell rule stops running on Linux and macOS, or starts running on Windows |
| `the_macos_web_server_rule_does_not_fire_on_a_linux_host` | the macOS web-server rule leaks onto Linux |

### YARA: `crates/yara/tests/content.rs`

[Source](https://github.com/synthaea-lab/agent/blob/main/crates/yara/tests/content.rs).

| Test | Fails when |
| --- | --- |
| `every_shipped_rule_compiles` | any file fails to compile, a rule lacks valid metadata, or no rule compiles |
| `every_shipped_rule_fires_on_its_sample` | a rule misses its sample, or the sample table and the compiled identifiers differ |
| `every_shipped_rule_ignores_its_negative_sample` | any rule fires on another rule's near miss, or the tables differ |

### IOC feeds: `crates/intel/tests/content.rs`

[Source](https://github.com/synthaea-lab/agent/blob/main/crates/intel/tests/content.rs).
`every_shipped_ioc_feed_loads_whole` loads each `ioc/*.txt` with the device's own parser and fails
on a rejected line, an indicator over the memory budget, or a feed with no indicator. It passes
vacuously while `ioc/` does not exist. The server repository's
[`tests/unit/ioc-content.test.ts`](https://github.com/synthaea-lab/server/blob/main/tests/unit/ioc-content.test.ts)
adds the checks only the server can make: public suffixes, duplicate indicators and the feed file
name.

## What the suites do not check

The suites prove that a rule loads, fires on the event its author wrote and ignores one near miss.
They do not prove:

- that real sensors produce the event the sample describes (path form, quoting, `argv[0]`). Only a
  run on a lab host does; the [scenarios](https://github.com/synthaea-lab/scenarios) repository
  drives real techniques against a live agent;
- the false-positive rate on ordinary activity;
- conventions the engine does not enforce: title uniqueness, file naming, coverage tags, the
  quality of a description;
- that the agent's generated ATT&CK coverage page is current. That check runs in the agent
  repository (see [step 8 of the walkthrough](writing-a-rule.md#8-keep-the-agents-coverage-page-in-step)).

Reviewers check those by hand.

## Pull request checks

Two workflows are defined in this repository:

| Workflow | What it runs |
| --- | --- |
| [`content.yml`](../.github/workflows/content.yml) | checks out this repository and the agent's `main` side by side, with `SYNTHAEA_REQUIRE_SIBLINGS=1`, and runs `cargo test --test content` for `sigma`, `yara` and `intel` |
| [`dco.yml`](../.github/workflows/dco.yml) | requires a Developer Certificate of Origin sign-off on every commit, through the organisation's shared workflow |

The content workflow does not run the Sigma platform test (`--test platform`), so a run of the
local commands above covers more than it does. A pull request that depends on an unmerged agent
change (a new YARA sample, a new engine feature) fails against the agent's `main` until that change
lands. Hosted CI does not run on every pull request, so the local commands are the gate: run all
of them with `SYNTHAEA_REQUIRE_SIBLINGS=1` before asking for review, and say so in the pull
request.
