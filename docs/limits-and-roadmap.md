# Limits and roadmap

What this content and the engines that run it do not do today. Each limit is stated so that a
missing detection is not mistaken for a clean host.

## Coverage

- **The rule set is small.** 39 Sigma rules (15 in `linux/`, 23 in `windows/`, 1 in `macos/`),
  3 YARA rules and no IOC feed. Most ATT&CK techniques have no rule here. Some have native
  detections in the agent instead; the agent's
  [coverage page](https://github.com/synthaea-lab/agent/blob/main/docs/attack-coverage.md) shows
  both.
- **macOS has one rule of its own.** It also runs the 15 Unix-family rules of `linux/`, but
  macOS-specific techniques (launch agents, `osascript`, TCC abuse) have no Sigma content.
- **Rules match command-line text.** A renamed binary defeats `Image|endswith`, and a different
  spelling of the same arguments (another flag order, extra quoting, an equivalent tool) defeats
  `CommandLine|contains`. Each rule's description says which forms it covers; nothing beyond them
  is implied.
- **Rules observe the command, not its outcome.** A match means the command was started, not that
  it succeeded.
- **The YARA rules are narrow by design.** The web shell rules match a sink called directly on
  request input; routing the same input through a variable first is a documented miss.

## Sigma engine

These come from the engine, and content cannot work around them:

- **Process creation only.** No file, network, registry, image-load, DNS or service events reach
  Sigma; those behaviours belong to the agent's native rules.
- **Single events only.** No aggregation, `near`, `timeframe` or correlation: a sequence such as
  "download, then execute" is not expressible.
- **Three fields in practice.** `Image`, `CommandLine` and `ParentImage`. The four Windows PE
  version fields validate, but in the running agent Sigma evaluates an event before the
  enrichment worker has read them, so a rule that needs one does not match yet. No shipped rule
  uses them.
- **Lineage can be missing.** A rule on `ParentImage` cannot fire when the sensor supplied no parent
  image for the event.
- **No regular expressions and no interior wildcards.**
- **A broken rule on a host is skipped, not fatal.** The agent logs a warning and keeps the other
  rules. That keeps a host detecting, but it also means the content suites are the only reliable
  place a broken rule is caught.
- **Titles are identities but uniqueness is not enforced.** Two rules with the same title would
  both load, and their detections could not be told apart. Review is the only check.
- **No Linux-only directory.** A rule in `linux/` also runs on macOS. A rule that must not run on
  macOS has nowhere to go; the alternative layout, a shared `unix/` directory, has not been
  adopted.

## Content validation

- **One near miss per Sigma rule.** The suites prove a boundary, not a false-positive rate. Nothing
  measures how often a rule fires on ordinary activity.
- **Samples are hand-written events.** They are not captured from sensors, so a sample can describe
  a path or quoting form that a real sensor never produces. Only a lab run shows that.
- **PE version fields cannot be sampled.** The samples schema has no key for them.
- **YARA samples live in the agent repository.** Every YARA change needs two coordinated pull
  requests.
- **Several Sigma rules are pinned by title in the agent's tests.** Renaming them, or shrinking
  their value lists, needs an agent change too (listed in [Sigma samples](samples.md#what-one-pair-cannot-cover)).
- **The catalog is maintained by hand.** The agent's coverage page is generated; [catalog.md](catalog.md)
  is not.

## Delivery

- **Not bundled.** Agent packages ship without this content; it has to be copied onto a host or
  delivered by a control plane.
- **No production signing yet.** The agent verifies content manifests against its `content` key,
  but the production keys are not provisioned in packaged builds. Until they are, content on a
  production host is a file someone placed there.
- **No targeting by category.** Content cannot yet be restricted to lab or development agents, so
  the `lab` YARA category reaches every agent that loads this content.
- **Platform gaps in the YARA path.** Process-memory scanning runs on Linux only, and quarantine on
  a match is available on Linux only. Windows and macOS hosts report a match without acting on it.

## Roadmap

The planned work tracked in this repository:

- **An upstream content channel for self-hosted servers**
  ([issue](https://github.com/synthaea-lab/rules/issues/1)): a self-hosted control plane receives
  official rules, IOC feeds and models as releases signed with the `content` key, and promotes them
  through its rings, instead of building content from a local checkout.

Engine-side changes that would lift the limits above (more Sigma fields, PE fields at evaluation
time, memory scanning on more platforms) are tracked in the
[agent repository](https://github.com/synthaea-lab/agent/issues).
