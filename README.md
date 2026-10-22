# LADE

LADE is Dominion's DevSecOps post-commit forensics and incident-autopsy tool. It investigates CI/CD pipelines, container activity, and runtime evidence to explain incidents and improve software delivery.

## Five-phase investigation workflow
1. **Plan (Planner):** define the incident questions, scope, evidence sources, and competing explanations.
2. **Collect:** gather and preserve relevant CI/CD, container, and runtime evidence.
3. **Execute (Executor):** run focused evidence queries and correlate events across systems.
4. **Analyze (Analyst):** test competing explanations, document uncertainty, and identify the best-supported findings.
5. **Report and remediate:** produce an auditable post-mortem and a draft remediation merge request.

## CLI and MCP server
Use the LADE CLI to run investigations. Start the MCP server with `lade serve` to make investigation capabilities available to MCP clients.

## License
MIT.
