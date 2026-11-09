# Repository layout and delivery

This page describes the tree, what each directory means to an agent, and the two ways content
gets from this repository onto a host.

## The tree

```text
sigma/
  linux/      <rule>.yml + <rule>.samples.json   Unix-family command-line rules
  windows/    <rule>.yml + <rule>.samples.json   Windows rules
  macos/      <rule>.yml + <rule>.samples.json   macOS-only rules
yara/
  webshell/   <rule>.yar                         web shell shapes
  lab/        <rule>.yar                         marker for benign lab payloads
ioc/          <feed>.txt                         IOC feeds (none shipped yet)
```

| Path | Format | Engine in the agent | Reference |
| --- | --- | --- | --- |
| [`sigma/`](../sigma/) | Sigma YAML, one rule per file, plus a samples file | [`sigma`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/src/lib.rs) | [sigma-rules.md](sigma-rules.md), [samples.md](samples.md) |
| [`yara/`](../yara/) | YARA source, compiled with YARA-X | [`yara`](https://github.com/synthaea-lab/agent/blob/main/crates/yara/src/lib.rs) | [yara-rules.md](yara-rules.md) |
| `ioc/` | one indicator per line | [`intel`](https://github.com/synthaea-lab/agent/blob/main/crates/intel/src/lib.rs) | [IOC feeds](#ioc-feeds) below |

The directory a file sits in is part of its meaning. For Sigma it decides which hosts run the
rule; for YARA the category directory is only organisational, because every `.yar` file is
compiled into one rule set.

## Which Sigma directory a host loads

The agent calls
[`SigmaEngine::load_dir_for`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/src/engine.rs)
with its own platform. [`Platform::rule_dirs`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/src/engine.rs)
fixes the set:

| Host | Loads |
| --- | --- |
| Linux | `sigma/linux/` |
| Windows | `sigma/windows/` |
| macOS | `sigma/macos/` and `sigma/linux/` |

Consequences for content:

- **`linux/` means "Unix-family command lines".** Shells, `curl`, `base64` and the GNU/BSD tools
  behave close enough on macOS that those rules are worth running there too. A rule in `linux/`
  that only makes sense on Linux (systemd, `auditctl`, `setcap`) costs nothing on macOS, because
  the binaries it keys on are absent. A rule that must not run on macOS has no place to go today:
  see [Limits and roadmap](limits-and-roadmap.md).
- **`macos/` is for macOS-only behaviour.** Put a rule there when it would be noise or meaningless
  on Linux, for example the web-server lineage rule
  [`web_server_spawned_shell.yml`](../sigma/macos/web_server_spawned_shell.yml), whose Linux
  counterpart is a native rule in the agent.
- **A rule outside the three directories runs nowhere.** The loader walks only
  `<root>/<platform>/`, and validation refuses a rule whose path under the root has no platform
  directory. Subdirectories below a platform directory are allowed and load with it.
- **The platform comes from the path under `sigma/`, never from the rest of the path.** A content
  root such as `/home/linux/content` does not turn a `windows/` rule into a Linux one. The agent's
  [`tests/platform.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/tests/platform.rs)
  pins this.

The split is enforced in validation as well as in loading: the four Windows PE version fields
(`OriginalFileName`, `Company`, `Description`, `Product`) are refused in `linux/` and `macos/`
rules, because they would load and never match on the hosts that run them.

## Mapping onto an agent's content directory

The agent reads every kind of content from one directory, the content root:

| In this repository | On the agent |
| --- | --- |
| `sigma/` | `<content-dir>/rules/sigma/` |
| `yara/` | `<content-dir>/rules/yara/` |
| `ioc/<feed>.txt` | `<content-dir>/ioc/<feed>.txt` |

The content root defaults to `<storage.state_dir>/content`
([`default_content_dir`](https://github.com/synthaea-lab/agent/blob/main/apps/agent/src/content.rs)).
`agent run --content-dir <dir>` overrides it; a relative value is tried next to the agent binary
first, then against the working directory
([`resolve_content_root`](https://github.com/synthaea-lab/agent/blob/main/apps/agent/src/sink/mod.rs)).

Note the asymmetry: Sigma and YARA rules live under `rules/` on the agent, IOC feeds do not. That
is why a checkout of this repository named `rules` can serve directly as the `rules/` part of a
content root, while a feed has to be placed one level up.

## Getting content onto a host

### By hand, for a lab

The agent packages do not bundle this content. On a test machine:

```sh
# as root, with storage.state_dir = /var/lib/synthaea (the Linux package layout)
mkdir -p /var/lib/synthaea/content/rules
cp -r sigma yara /var/lib/synthaea/content/rules/
```

or point the agent at a directory that holds this checkout as `rules/`:

```sh
mkdir -p ~/content
git clone https://github.com/synthaea-lab/rules ~/content/rules
agent run --content-dir ~/content
```

Restart the agent afterwards: content copied by hand is read at startup. Content placed by hand is
not signed. That is acceptable on a lab machine and nowhere else.

### Through a control plane

A self-hosted [server](https://github.com/synthaea-lab/server) distributes content as a signed
manifest per rollout ring (`canary_0`, `canary_1`, `canary_2`, `prod`). The agent fetches the
manifest for its ring, checks the signature against its `content` key, downloads each entry with
its declared size and hash, writes it atomically under the content root, and then asks the running
agent to reload. The full procedure, including rollback by corrective release, is in the agent's
[content delivery](https://github.com/synthaea-lab/agent/blob/main/docs/updates-and-releases.md#content-delivery)
page.

Today a server builds that content from a local checkout of this repository. There is no upstream
release channel from this repository to self-hosted servers yet; see
[Limits and roadmap](limits-and-roadmap.md#roadmap).

## Loading and reload on the agent

Content is loaded at startup and again on a reload. A reload is the `ReloadContent` request over
the local IPC channel, which `apply-content-manifest` sends after it writes new content; there is
no operator command for it, so content placed by hand takes effect at the next agent start. Each
engine reports one of three outcomes, and the outcome decides what a bad change does to a running
host:

| Outcome | Sigma | YARA | IOC |
| --- | --- | --- | --- |
| Directory absent | engine unloaded | engine unloaded | set unloaded |
| One file broken | **that rule skipped**, warning names the file and reason; the rest loads | **whole load fails**: on a reload the previous rule set is kept, at startup YARA stays off | bad lines counted and skipped; the rest of the feed loads |
| Directory unreadable | on a reload the previous engine is kept, at startup none loads | same as Sigma | same as Sigma |

The asymmetry between Sigma and YARA comes from the engines: Sigma rules are independent
documents, while YARA-X compiles every file into one rule set. Either way a running host never
loses detection because of a broken file, but a broken Sigma rule silently stops detecting on the
host while still passing as "loaded". That is why the content suites treat any skip as a failure
(see [Testing and validation](testing.md)).

## IOC feeds

The repository has no `ioc/` directory yet. The format and the checks are in place so that a feed
can be added without new tooling:

- one feed per file, `ioc/<feed>.txt`, the file stem being the feed name. The server's check
  requires a name of lowercase letters, digits, `.`, `_` and `-`;
- one indicator per line, `#` comments and blank lines ignored:

  ```text
  # comment
  sha256:<64 hex digits>
  ip:<IPv4 or IPv6 address, no CIDR, no loopback>
  domain:<ASCII DNS name, 2 to 8 labels, punycode for IDNs>
  ```

- a listed domain matches every name beneath it, and the agent carries no public-suffix list, so a
  public suffix such as `co.uk` must never be listed. The server's check refuses one;
- an IOC match is reported, never acted on: it does not kill or quarantine.

The agent's [IOC page](https://github.com/synthaea-lab/agent/blob/main/docs/detection/ioc.md#feed-format)
is the reference for the line grammar and the matching semantics.
