# ASPICE-oriented Spring Boot CI demo

A small Java 21 / Spring Boot REST service intended for an ASPICE hackathon demonstration.

## Run locally

Prerequisites: JDK 21 and Maven 3.9+.

```bash
mvn clean verify
mvn spring-boot:run
```

Try:
- `GET http://localhost:8080/api/status`
- `GET http://localhost:8080/api/health` — returns the application health status as JSON.
- `GET http://localhost:8080/actuator/health`

The `/api/health` endpoint is a GET request with no request body. It returns `application`, `status`, and an ISO-8601 UTC `timestamp`. The existing `/api/status` endpoint remains available. The requirement and acceptance criteria are tracked in [Jira issue SCRUM-6](https://faizalmohameds620.atlassian.net/browse/SCRUM-6).

## Build and run with Docker

```bash
docker build -t aspice-demo:local .
docker run --rm -p 8080:8080 aspice-demo:local
```

## GitHub Actions

The workflow at `.github/workflows/ci.yml` also provides:

- A Jira-backed pull request traceability gate: include an existing issue key from the `SCRUM` project (for example `SCRUM-6`) in the PR title or description. The workflow verifies the issue through Jira's REST API and requires the `aspice-requirement` label.
- A CycloneDX software bill of materials (SBOM), saved as a 90-day workflow artifact and summarized in the final ASPICE report.
- Maven build and JUnit/JaCoCo verification reports.
- SonarCloud quality analysis and Trivy filesystem and image scan evidence.
- An ASPICE evidence report and HTML deployment to GitHub Pages.
- A Docker image published to GHCR after the image scan on non-PR runs.

Push this project to a GitHub repository with its default branch named `main`. No personal access token is needed for GHCR when the workflow's `GITHUB_TOKEN` has package write permission. Depending on repository/org package settings, you may need to make the package visible or link it to the repository.

For Jira traceability, configure the repository Actions secrets `JIRA_BASE_URL`, `JIRA_EMAIL`, and `JIRA_API_TOKEN`. The token is used only by the pull request traceability job and must not be committed to the repository.

## ASPICE hackathon demonstration mapping

This is an engineering workflow example, **not an ASPICE compliance claim or certification**. Adapt the process to your organization's defined processes and assessment scope.

| Demonstration evidence | Where it comes from |
|---|---|
| Change / requirement traceability | Link each pull request to a requirement or work-item ID; include the ID in PR title/description |
| Verification evidence | JUnit test source and Surefire XML reports |
| Build reproducibility | Maven build in the GitHub Actions run |
| Configuration / version identification | Git commit SHA used as the Docker image tag |
| Release / deployment package | Container image published to GHCR after CI passes |
| Vulnerability management | Trivy image scan output and pipeline gate |

## Requirement traceability demonstration

Create and maintain requirements in Jira, apply the `aspice-requirement` label, then reference the Jira issue key in each pull request. The traceability job confirms that each referenced issue exists in the configured Jira project and carries that label. Use the job result, test reports, SBOM, security scans, and generated report as objective evidence. This is an engineering workflow example, not an ASPICE compliance claim or certification.
