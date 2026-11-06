# Bugs

Confirmed issues of the audit, ordered by severity. Severities, roles and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it exits 1 while the bug is
present and 0 once it is fixed. IDs take the form `R<round>-<ANGLE>-<n>`: the round, the hunter's angle, and the
candidate's number within that angle.

Flags required by `AUDIT.md` (fallback-only confirmations, issues without a proof of concept, tests that model a
component instead of running it):

- None yet.

| ID | Title | Component | Role | Cited rules | Severity |
|---|---|---|---|---|---|

<!--
Template for each issue. Copy it below the index, in the same order as the index.

## <ID>

**Title.** <one line>

**Severity.** <Critical | High | Medium>

### Problem

<What goes wrong, and how it threatens the security goal of section 1, or why it still violates a rule.>

### Component, role and area

<The component, its role from the AUDIT.md table, and the area within it.>

### Location

<Files and functions.>

### Evidence and test

<What `bugs/<ID>/` contains (test, guest programs, configurations, crafted logs or proofs, inputs, scripts), how to
run it, and what it prints on audit/prt2. Say which model found, proved and reviewed it if a fallback was used.>

### Trigger and reachability

<Who triggers it and how. For an unreachable state, why no input sequence from any valid template produces it.>

### Rating

1. Out of scope: <why not, quoting the exclusions checked>.
2. Role: <component and role, quoting section 3>.
3. High and Medium cases: <the case that fits, quoted, or why none does>.
4. Critical: <the rule or obligation violated at a reachable state or on the honest operator's path, quoted>.

<If two readings give different classes, give both and the facts that would decide.>

### Possible solution and risks

<The fix, and what it could break.>

### Risk of not fixing it

<What a deployment that leaves it unfixed is exposed to, who can trigger it, and any mitigation outside the code.>
-->
