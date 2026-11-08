# REQ-API-001: Retrieve application health status

## Requirement

The service shall provide a read-only HTTP endpoint for retrieving the current application health status in a structured JSON response.

## Request

- Method: `GET`
- Path: `/api/health`
- Request body: none. The health endpoint does not require request parameters.
- Accepted response type: `application/json`

Example:

```http
GET /api/health HTTP/1.1
Accept: application/json
```

## Successful response

Status: `200 OK`

```json
{
  "application": "aspice-demo",
  "status": "UP",
  "timestamp": "2026-11-08T10:15:30Z"
}
```

The timestamp is generated for each request in ISO-8601 UTC format. `/api/status` remains available and returns the same response for compatibility.

## Acceptance criteria

1. A GET request to `/api/health` returns `200 OK` and a JSON response.
2. The response includes `application` equal to `aspice-demo`, `status` equal to `UP`, and a valid ISO-8601 timestamp.
3. The endpoint is read-only and does not require a request body.
4. `/api/status` continues to return the same health response.

## Verification evidence

The requirement ID in the pull request links the API change to this contract. The CI run provides build and verification evidence.
