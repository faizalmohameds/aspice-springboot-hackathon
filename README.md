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

The workflow at `.github/workflows/ci.yml`:
1. Builds and tests the application on pull requests and pushes to `main`.
2. Uploads JUnit/Surefire test reports as a workflow artifact.
3. Builds a Docker image and fails the pipeline for HIGH/CRITICAL Trivy findings (unfixed findings are ignored).
4. Publishes the image to GitHub Container Registry (GHCR) only after a successful `main` push.

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

## Suggested hackathon extension

Add a `REQ-001` work item for the status endpoint, reference it in the pull request, add a corresponding test, and show the GitHub Actions run as objective evidence that the change was built and verified.
