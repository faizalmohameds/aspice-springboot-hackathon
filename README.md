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
- `GET http://localhost:8080/actuator/health`

## Build and run with Docker

```bash
docker build -t aspice-demo:local .
docker run --rm -p 8080:8080 aspice-demo:local
```

## GitHub Actions

The workflow at `.github/workflows/ci.yml` also provides:

- A pull request traceability gate: include a registered requirement ID (for example `REQ-CI-001`) in the PR title or description. The ID must have a matching Markdown record under `docs/requirements/`.
- A CycloneDX software bill of materials (SBOM), saved as a 90-day workflow artifact.
- Maven build and JUnit/JaCoCo verification reports.
- SonarCloud quality analysis and Trivy filesystem and image scan evidence.
- An ASPICE evidence report and HTML deployment to GitHub Pages.
- A Docker image published to GHCR after the image scan on non-PR runs.

Push this project to a GitHub repository with its default branch named `main`. No personal access token is needed for GHCR when the workflow's `GITHUB_TOKEN` has package write permission. Depending on repository/org package settings, you may need to make the package visible or link it to the repository.

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

`docs/requirements/REQ-CI-001.md` defines the pull request traceability requirement and acceptance criteria. Reference the ID in a pull request and use the traceability job result, test reports, SBOM, security scans, and generated report as objective evidence. This is an engineering workflow example, not an ASPICE compliance claim or certification.
