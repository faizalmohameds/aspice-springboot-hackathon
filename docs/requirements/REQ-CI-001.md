# REQ-CI-001: Pull request requirement traceability

## Requirement

Every pull request that changes the application or its build and delivery workflow shall identify at least one approved requirement ID in its title or description. The referenced ID shall have a matching requirement record in `docs/requirements/`.

## Rationale

This provides a lightweight, reviewable link from a change to its intended need. It supports the hackathon's ASPICE process demonstration; it does not claim ASPICE compliance.

## Acceptance criteria

1. A pull request containing a registered ID such as `REQ-CI-001` in its title or description passes the traceability check.
2. A pull request with no requirement ID fails with an actionable message.
3. A pull request referencing an ID without a matching `docs/requirements/<ID>.md` record fails.
4. Push and manual workflow runs do not require pull request metadata.

## Verification evidence

The `requirement-traceability` GitHub Actions job records the check result. The requirement document and pull request provide the source and change link.
