# Sigma rule format

A Sigma rule in this repository is a standard [Sigma](https://sigmahq.io) document restricted to
what the agent's engine supports, plus a few metadata requirements and conventions. The
authoritative definition of the subset is the agent's
[Sigma engine page](https://github.com/synthaea-lab/agent/blob/main/docs/detection/sigma.md#supported-subset);
this page explains it from the point of view of someone writing content, and adds the
conventions the engine does not enforce.

## A complete rule

[`sigma/windows/security_service_start_disabled.yml`](../sigma/windows/security_service_start_disabled.yml):

```yaml
title: Security service configured with disabled startup
description: >
  Detects sc.exe requesting disabled startup for Defender, Defender for Endpoint
  or Sysmon. The exact service and startup value distinguish this from routine
  service queries or unrelated service configuration; success is not observed.
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - synthaea.coverage.defense_evasion
level: medium
falsepositives:
  - Security administrators removing or replacing an agent, rebuilding an image
    or changing a lab's instrumentation under an approved maintenance plan.
detection:
  selection:
    Image|endswith: '\sc.exe'
    CommandLine|contains:
      - ' config WinDefend start= disabled'
      - ' config Sense start= disabled'
      - ' config Sysmon start= disabled'
      - ' config Sysmon64 start= disabled'
  condition: selection
```

## Top-level keys

The engine deserialises the keys below into
[`SigmaRule`](https://github.com/synthaea-lab/agent/blob/main/crates/sigma/src/rule.rs) and ignores any
other key (`id`, `status`, `author`, `references`, `date`), so upstream rules keep loading. Keys the
engine ignores carry no meaning on the agent; this repository does not use them.

| Key | Required | Enforced by | Meaning on the agent |
| --- | --- | --- | --- |
| `title` | yes | parser | The rule's identity: it becomes the detection's `rule_id` and the name in alert lines. Keep it unique across the repository. |
| `description` | convention | nobody | For reviewers and readers: the agent's detection carries the title, not the description. Say what the rule matches, what it deliberately does not, and why the boundary sits where it does. |
| `tags` | yes, with at least one `attack.tNNNN[.NNN]` | validation | Techniques for the detection; see [Tags](#tags). |
| `level` | yes | parser and validation | Severity: `informational` (mapped to low), `low`, `medium`, `high`, `critical`. Any other value is a parse error. |
| `falsepositives` | yes, non-empty | validation | Known benign causes. If none are known, say so and why. |
| `logsource` | no | validation | Omitted in every rule here; absent means `process_creation`. See [Log source](#log-source). |
| `detection` | yes | parser and validation | Named blocks plus `condition`. |

A rule that fails any check is refused at load with a message naming the file and the reason, for
example `missing falsepositives` or `no ATT&CK technique tag in tags`.

## Fields

Every field is read from the process-creation event the sensors produce
([`ExecEvent`](https://github.com/synthaea-lab/agent/blob/main/crates/schema/src/lib.rs)):

| Sigma field | What it holds | Notes |
| --- | --- | --- |
| `Image` | full path of the executed image | Windows paths use `\`, Unix paths `/`. |
| `CommandLine` | the full command line | Raw, before redaction: a rule sees exactly what ran. |
| `ParentImage` | full path of the parent's image | Absent when the sensor has no lineage. The field then never matches, and the rule cannot fire. |
| `OriginalFileName`, `Company`, `Description`, `Product` | PE version strings | `windows/` rules only. In the running agent these are not populated yet when Sigma runs; see [Limits](limits-and-roadmap.md#sigma-engine). |

Field names are case-insensitive. Any other field (`User`, `CurrentDirectory`, `Hashes`,
`IntegrityLevel`) is refused at load, naming it. All matching is case-insensitive: the event value
and the pattern are both lowercased.

## Modifiers and values

| Written as | Matches when the field value |
| --- | --- |
| `Field: 'x'` | equals `x` |
| `Field: '*x'`, `'x*'`, `'*x*'` | ends with, starts with, or contains `x` |
| `Field\|contains: 'x'` | contains `x` |
| `Field\|startswith: 'x'` | starts with `x` |
| `Field\|endswith: 'x'` | ends with `x` |
| `Field\|contains\|all: [a, b]` | contains every listed value (also with `startswith`, `endswith`) |

- A list of values is an OR; with `|all` it is an AND.
- Without a modifier, `*` is allowed only at the start or the end of a value. A `*` inside a value
  (`'C:\*\cmd.exe'`) is refused, because the engine has no general glob.
- **With a modifier, `*` is an ordinary character.** `CommandLine|contains: '*.ps1'` looks for the
  two characters `*.` literally. Use either a modifier or edge wildcards, not both.
- Empty value lists are refused, and so is the same field and modifier written twice in one block
  with different capitalisation.
- Not supported: `re`, `windash`, `base64`, `base64offset`, `cidr`, `fieldref`, `exists`, numeric
  comparisons and every other modifier. They are refused at load.

The same field may appear more than once in a block with different modifiers; the conditions are
ANDed. [`psexec_remote_inline_credentials.yml`](../sigma/windows/psexec_remote_inline_credentials.yml)
requires both `CommandLine: '* \\*'` (a UNC host anywhere) and `CommandLine|contains: ' -p '`.

One rule shows the edge-wildcard form at scale:
[`sigma/linux/curl_upload_to_cloud_storage.yml`](../sigma/linux/curl_upload_to_cloud_storage.yml)
lists host names as `'*drive.google.com*'`, which reads as "contains" without a modifier.

## Blocks and conditions

`detection` holds named blocks and one `condition`. A block has one of three shapes:

```yaml
detection:
  selection:            # a map: AND between fields
    Image|endswith: '/curl'
    CommandLine|contains: ' -T'
  either:               # a list of maps: OR between the maps
    - Image|endswith: '/wget'
    - Image|endswith: '/curl'
  keywords:             # a list of strings: matched against the whole command line
    - 'mimikatz'
  condition: selection and not either
```

The condition grammar is small and bounded: `and`, `or`, `not`, parentheses, block names,
`1 of <pattern>`, `all of <pattern>`, and `them`. A pattern is a block name or a prefix ending in
one `*` (`1 of filter_*`). Keywords are case-insensitive, block names are not.

What is refused, each with its reason:

- a block name or pattern that matches no block (a typo would otherwise make the condition
  vacuously true or false);
- aggregations and correlations: `count()`, `near`, any `|` pipe, `timeframe`;
- `any of`, and `N of` for any N other than 1;
- a condition over 1,024 bytes, 128 tokens, 8 levels of nesting, or 64 referenced blocks.

Only blocks the condition references are validated and evaluated. A block the condition never
mentions is dead text: the suite will not catch a mistake in it.

Every shipped rule today uses `condition: selection` with one map block. That is not a
requirement; it is what single-event, command-line detection usually needs.

## Log source

Leave `logsource` out. The engine treats a missing `logsource` as `process_creation`, the only
category it evaluates. When present, it is checked so that a rule written for other telemetry is
refused instead of being run against process creations:

| `logsource` | Result |
| --- | --- |
| absent | loads |
| `category: process_creation` | loads |
| `category: process_creation` and `product: <p>` | loads only if `<p>` is the rule's platform directory (`linux`, `windows`, `macos`) |
| any other `category` | refused, naming it |
| any `service` (`security`, `sysmon`, `auditd`) | refused: log channels are not mapped |
| a `logsource` without `category` (`product` alone included) | refused |

An upstream SigmaHQ `process_creation` rule can therefore be copied into the directory of its
product as-is, provided its fields and modifiers are in the subset and it carries the metadata
above.

## Tags

Tags do three jobs:

| Tag | Example | Used for |
| --- | --- | --- |
| `attack.tNNNN[.NNN]` | `attack.t1059.004` | Required (at least one). Scanned by the agent's ATT&CK coverage generator. |
| `attack.<tactic>` | `attack.credential_access` | Upstream Sigma convention; documents the tactic. |
| `synthaea.coverage.<area>` | `synthaea.coverage.credential_access` | Groups rules by the coverage area they were written for. |

The coverage areas in use are `initial_access_user_execution`, `credential_access`,
`defense_evasion`, `discovery_lateral`, `collection_exfiltration` and `privesc_impact`. The engine
does not interpret them; the server's hunt-to-rule draft asks the author to set one. A few older
rules have none. New rules should carry one.

The agent labels a Sigma detection with **all** of the rule's tags joined with `/`, tactic and
coverage tags included, and stores the same list, split again, as the detection's techniques.
Keep tags tidy and in a stable order: they appear in every alert, and changing them changes the
label the detection is fused under.

## YAML pitfalls

The agent parses rules with strict, explicit YAML settings. Some valid YAML is refused on purpose:

- **Duplicate keys are an error.** A second `selection:` would otherwise silently replace the
  first, and that would let a rule be weakened without a visible diff.
- **Merge keys (`<<`) and unknown tags are errors.**
- **Only `true` and `false` are booleans.** `yes`, `no` and `on` stay strings, so a value such as
  `- no` keeps meaning the text `no`.
- **Files over 1 MiB are refused**, and the parser has a node, depth and alias budget sized for a
  rule.

Quoting matters for Windows paths. Use single quotes, where a backslash is literal:

```yaml
Image|endswith: '\sc.exe'        # one backslash, as on disk
CommandLine|contains: '\\'       # two backslashes: a UNC prefix
```

In double quotes, `"\sc.exe"` is an invalid escape and the file does not parse.

## What a match becomes

On the agent, every exec event is evaluated against the loaded rules on the capture thread
([`DetectionSink::detect_exec`](https://github.com/synthaea-lab/agent/blob/main/apps/agent/src/sink/mod.rs)).
Each matching rule becomes a detection with:

| Detection field | Value |
| --- | --- |
| source | `Sigma { rule_id: <title> }` |
| title | the rule's `title` |
| severity | the rule's `level` (`informational` becomes low) |
| techniques | the rule's tags, as written |
| events | the exec event, redacted |

The detection is fused into the verdict of the process that ran the command, written to the alert
log and, when a control plane is configured, spooled for upload. A Sigma detection does not by
itself kill or quarantine anything; the agent's
[response page](https://github.com/synthaea-lab/agent/blob/main/docs/response.md) describes when
the agent acts.

The rule matched the raw command line, but the copy that enters the verdict, the alert log and the
upload goes through the agent's redaction first. A rule can therefore key on a secret-looking
argument without the matched value having to appear in the outputs; which patterns are redacted,
and which are not, is in the agent's
[redaction page](https://github.com/synthaea-lab/agent/blob/main/docs/redaction.md).

## Naming and style conventions

- File name: lowercase, `snake_case`, describing the behaviour, without a platform prefix
  (`sigma/windows/ntds_ifm_export.yml`, not `win_ntds.yml`). The platform is the directory.
- Extension: `.yml`. The engine also loads `.yaml`, but the agent's platform test counts only
  `.yml` files, so a `.yaml` rule makes that test fail.
- One rule per file, one samples file per rule.
- Title: a sentence describing the observed behaviour, unique in the repository. It is the rule's
  identifier everywhere downstream, so renaming a title is a breaking change for anyone who
  suppressed or queried detections by it.
- Description: what is matched, what is deliberately left out, and that the rule observes a
  submitted command rather than its success, when that matters.
- Prefer argument-shaped boundaries (`' config WinDefend start= disabled'` with its leading space)
  over bare words, and record the boundary you chose in the samples file's near miss.
