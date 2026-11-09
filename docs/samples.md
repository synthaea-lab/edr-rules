# Sigma samples

Every Sigma rule has a samples file beside it: `<rule>.yml` and `<rule>.samples.json` in the same
directory. The file holds one event the rule must match and one near miss it must ignore. The
agent's content suite reads it, builds two process-creation events from it, and runs them through
the real engine.

Samples are data rather than test code so that a rule and its proof travel together. A pull
request that adds a rule is complete in this repository alone, and a tool that drafts a rule (such
as the server's hunt-to-rule draft) can emit both files without touching the agent.

## Schema

```json
{
  "matching": {
    "image": "/usr/bin/cp",
    "cmdline": "cp --preserve=mode /etc/shadow /root/shadow.backup"
  },
  "non_matching": {
    "image": "/usr/bin/cp",
    "cmdline": "cp --preserve=mode /etc/shadow.example /root/shadow.example.backup",
    "note": "A filename sharing the prefix is not the live password database; the argument boundary matters."
  }
}
```

(from [`sigma/linux/shadow_file_copy.samples.json`](../sigma/linux/shadow_file_copy.samples.json))

| Key | Type | Required | Becomes |
| --- | --- | --- | --- |
| `matching` | object | yes | an event the rule must fire on |
| `non_matching` | object | yes | an event no rule in the repository may fire on |
| `<sample>.image` | string | yes | `Image` (`ExecEvent::image_path`) |
| `<sample>.cmdline` | string | yes | `CommandLine` (`ExecEvent::cmdline`) |
| `<sample>.parentimage` | string | no | `ParentImage` (`ExecEvent::parent_image_path`); absent means "no lineage" |
| `<sample>.note` | string | no | nothing; documents why the event is there |

The structs are
[`Samples` and `Sample`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/content.rs),
deserialised with `deny_unknown_fields`: a misspelt key (`cmdLine`, `parent_image`) is an error,
not a silently ignored field. The four Windows PE version fields cannot be set from a samples file
today, so a rule that keys on them cannot be proven by the suite; see
[Limits and roadmap](limits-and-roadmap.md#content-validation).

## How a sample becomes an event

The suite starts from the schema crate's fixture event and overrides three fields:

```rust
ExecEvent {
    meta: EventMeta { pid: 1, comm: "test".into(), ..schema::fixtures::meta() },
    image_path: sample.image.clone(),
    cmdline: sample.cmdline.clone(),
    parent_image_path: sample.parentimage.clone(),
    ..schema::fixtures::exec()
}
```

Everything else (user, timestamps, hashes, PE strings) comes from the fixture and is irrelevant to
the engine, which reads only the fields above. Write `image` as the full path a sensor would
report on that platform (`C:\Windows\System32\sc.exe`, `/usr/bin/curl`) and `cmdline` as the
process's full command line, including `argv[0]`. JSON strings need `\\` for a Windows
backslash.

## The two checks

For each rule file, the suite loads the whole `sigma/` tree once with
`SigmaEngine::load_dir` and then:

1. evaluates `matching` and requires that **this rule's title** is among the hits;
2. evaluates `non_matching` and requires that **no rule at all** fires.

The second check is stricter than it looks. A near miss for one rule must not trip any other rule
in the repository, on any platform: the suite loads every platform directory together, not just
the rule's own. If your near miss legitimately matches another rule, choose a different one.

The matching sample may trigger other rules as well. Overlap between rules is allowed; for
example, a remote `sc.exe` service creation raises both
[`service_created_with_shell_binpath.yml`](../sigma/windows/service_created_with_shell_binpath.yml)
and [`remote_service_shell_command.yml`](../sigma/windows/remote_service_shell_command.yml) by
design.

## Pairing

A separate test walks the tree and requires a one-to-one pairing:

- a `.yml` or `.yaml` rule with no `<rule>.samples.json` fails as dead content, naming both files;
- a `.samples.json` with no rule beside it fails as stale (left behind by a rename or a removal).

## Choosing a near miss

The negative sample is the most useful line in the file. A benign command picked at random
(`ls -la`) proves nothing: it would pass against an empty rule. A near miss probes the rule's
actual boundary, so that loosening the rule by mistake makes the test fail:

| Rule boundary | Near miss used |
| --- | --- |
| an exec flag on a network tool | `nc -zv host 22`: the same binary, no `-e` ([`reverse_shell`](../sigma/linux/reverse_shell.samples.json)) |
| an exact argument | `/etc/shadow.example`: shares the prefix ([`shadow_file_copy`](../sigma/linux/shadow_file_copy.samples.json)) |
| a parent process | `launchd` starting the same shell ([`web_server_spawned_shell`](../sigma/macos/web_server_spawned_shell.samples.json)) |

State the boundary in `note`, starting with what makes the event benign. A reviewer should be able
to read the note and know which change to the rule would break the test.

## What one pair cannot cover

One matching event cannot show every value of a list. For rules whose lists are the point (the
cloud-storage and paste-service host lists, the web-server parent lists, the local and remote
service split), the agent's
[`tests/content.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/content.rs)
carries additional table-driven tests that look rules up **by title**. Renaming one of those rules,
or removing a listed value, fails those tests and needs a matching change in the agent repository.
The titles involved are:

- `Linux curl uploads a file to a cloud storage endpoint`
- `Linux curl uploads a file to a paste service`
- `Service created with a command-shell binary path`
- `Remote service created with a command-shell binary path`
- `Web server or application server spawned a command interpreter`
- `Web server spawned a shell on macOS`
- `Reverse shell via /dev/tcp or nc/ncat with execution` (in
  [`tests/platform.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/platform.rs))
