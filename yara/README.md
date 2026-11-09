# YARA rules

File and process-memory content rules, compiled by the agent's
[`yara` engine](https://github.com/synthaea-lab/agent/blob/main/docs/detection/yara.md)
(YARA-X). Files follow `<category>/<family-or-technique>.yar`.

| Directory | Content |
| --- | --- |
| `webshell/` | Minimal PHP and JSP web shell shapes |
| `lab/` | A marker for the benign payloads dropped by lab scenarios |

Every rule carries `severity`, `technique` and `falsepositives` metadata, and every file must
compile. See [CONTRIBUTING.md](../CONTRIBUTING.md#yara-rules) for the conventions and for how
to run the content suite.
