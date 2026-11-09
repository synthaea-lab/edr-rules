# Sigma rules

Behavioral rules on process execution events, evaluated on the endpoint by the agent's
[`sigma` engine](https://github.com/synthaea-lab/agent/blob/main/docs/detection/sigma.md).

| Directory | Loaded on |
| --- | --- |
| `linux/` | Linux and macOS |
| `windows/` | Windows |
| `macos/` | macOS |

Each `<rule>.yml` has a `<rule>.samples.json` beside it, with one event the rule must match
and one near miss it must ignore. The engine refuses any rule outside its supported Sigma
subset at load time. See [CONTRIBUTING.md](../CONTRIBUTING.md#sigma-rules) for the rule and
sample conventions and for how to run the content suite.
