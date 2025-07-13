# KubeNexus API Reference

The KubeNexus platform provides a comprehensive REST API for programmatic access to all platform features. This documentation covers authentication, endpoints, request/response formats, and integration examples.

## Base URL

All API requests should be made to:
```
https://api.kubenexus.yourdomain.com
```

## API Documentation Structure

1. **[Authentication](authentication.md)**
   - JWT token authentication
   - API key management
   - Token refresh and validation

2. **[Users & Roles](users.md)**
   - User management
   - Role-based access control
   - Permission management

3. **[Cluster Management](clusters.md)**
   - Cluster CRUD operations
   - Cluster health and status
   - Resource management

4. **[Monitoring & Metrics](monitoring.md)**
   - Metrics collection and querying
   - Alert management
   - Performance data

5. **[SRE Agent](sre.md)**
   - Anomaly detection results
   - Recommendations and insights
   - Problem management

## Quick Start

### 1. Authentication

Obtain an access token:

```bash
curl -X POST https://api.kubenexus.yourdomain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your-username",
    "password": "your-password"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### 2. Using the API

Include the token in subsequent requests:

```bash
curl -X GET https://api.kubenexus.yourdomain.com/api/clusters \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 3. Common Operations

**List clusters:**
```bash
GET /api/clusters
```

**Get cluster details:**
```bash
GET /api/clusters/{cluster_id}
```

**Add new cluster:**
```bash
POST /api/clusters
```

## API Conventions

### HTTP Methods

- **GET**: Retrieve resources
- **POST**: Create new resources
- **PUT**: Update entire resources
- **PATCH**: Update partial resources
- **DELETE**: Remove resources

### Request Headers

All requests should include:

```
Authorization: Bearer YOUR_ACCESS_TOKEN
Content-Type: application/json
Accept: application/json
```

### Response Format

All responses follow a consistent format:

**Success Response:**
```json
{
  "status": "success",
  "data": {
    // Response data
  },
  "message": "Operation completed successfully"
}
```

**Error Response:**
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {}
  }
}
```

### Status Codes

- **200 OK**: Successful GET, PUT, PATCH requests
- **201 Created**: Successful POST requests
- **204 No Content**: Successful DELETE requests
- **400 Bad Request**: Invalid request format or parameters
- **401 Unauthorized**: Authentication required or invalid
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Resource conflict (e.g., duplicate names)
- **422 Unprocessable Entity**: Validation errors
- **500 Internal Server Error**: Server-side errors

## Pagination

For endpoints that return lists, pagination is handled via query parameters:

```bash
GET /api/clusters?page=1&limit=20&sort=name&order=asc
```

Parameters:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `sort`: Sort field (default: varies by endpoint)
- `order`: Sort order (`asc` or `desc`, default: `asc`)

Response includes pagination metadata:
```json
{
  "status": "success",
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "pages": 8,
    "has_next": true,
    "has_prev": false
  }
}
```

## Filtering and Search

Many endpoints support filtering and search:

```bash
GET /api/clusters?status=active&provider=aws&search=production
```

Common filter parameters:
- `status`: Filter by status
- `provider`: Filter by cloud provider
- `region`: Filter by region
- `search`: Full-text search across relevant fields

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Default Limit**: 1000 requests per hour per user
- **Burst Limit**: 100 requests per minute

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

When rate limits are exceeded, a `429 Too Many Requests` status is returned.

## Webhooks

KubeNexus supports webhooks for real-time notifications:

### Webhook Events

- `cluster.created`: New cluster added
- `cluster.updated`: Cluster configuration changed
- `cluster.deleted`: Cluster removed
- `alert.triggered`: New alert generated
- `anomaly.detected`: SRE agent detected anomaly
- `recommendation.created`: New SRE recommendation

### Webhook Configuration

Configure webhooks via the API:

```bash
POST /api/webhooks
{
  "url": "https://your-service.com/webhook",
  "events": ["cluster.created", "alert.triggered"],
  "secret": "your-webhook-secret"
}
```

## SDKs and Client Libraries

Official SDKs are available for popular languages:

### Python
```bash
pip install kubenexus-sdk
```

```python
from kubenexus import Client

client = Client(
    base_url="https://api.kubenexus.yourdomain.com",
    username="your-username",
    password="your-password"
)

clusters = client.clusters.list()
```

### JavaScript/Node.js
```bash
npm install kubenexus-sdk
```

```javascript
const KubeNexus = require('kubenexus-sdk');

const client = new KubeNexus({
  baseUrl: 'https://api.kubenexus.yourdomain.com',
  username: 'your-username',
  password: 'your-password'
});

const clusters = await client.clusters.list();
```

### Go
```bash
go get github.com/kubenexus/kubenexus-go
```

```go
import "github.com/kubenexus/kubenexus-go"

client := kubenexus.NewClient(&kubenexus.Config{
    BaseURL:  "https://api.kubenexus.yourdomain.com",
    Username: "your-username",
    Password: "your-password",
})

clusters, err := client.Clusters.List()
```

## Interactive API Explorer

KubeNexus provides an interactive API explorer at:
```
https://api.kubenexus.yourdomain.com/docs
```

Features:
- Browse all available endpoints
- Try API calls directly in the browser
- View request/response examples
- Download OpenAPI specification

## Error Handling

### Common Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `INVALID_CREDENTIALS` | Invalid username/password | Check credentials |
| `TOKEN_EXPIRED` | JWT token has expired | Refresh token |
| `INSUFFICIENT_PERMISSIONS` | User lacks required permissions | Contact admin |
| `CLUSTER_NOT_FOUND` | Cluster ID doesn't exist | Verify cluster ID |
| `VALIDATION_ERROR` | Request validation failed | Check request format |
| `RATE_LIMIT_EXCEEDED` | Too many requests | Wait and retry |

### Retry Logic

Implement exponential backoff for transient errors:

```python
import time
import random

def retry_request(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except TransientError:
            if attempt == max_retries - 1:
                raise
            wait_time = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(wait_time)
```

## Best Practices

### Security
- Store API credentials securely
- Use HTTPS for all requests
- Implement proper token refresh logic
- Validate SSL certificates

### Performance
- Use pagination for large datasets
- Implement client-side caching where appropriate
- Use appropriate timeouts
- Monitor rate limits

### Reliability
- Implement retry logic for transient failures
- Handle all possible HTTP status codes
- Use idempotent operations where possible
- Monitor API health and status

## Support

### Documentation
- **OpenAPI Spec**: Available at `/openapi.json`
- **Interactive Docs**: Available at `/docs`
- **ReDoc**: Available at `/redoc`

### Community
- **GitHub Issues**: Report bugs and request features
- **Stack Overflow**: Community Q&A with `kubenexus` tag
- **Discord**: Real-time community support

### Enterprise Support
- **Priority Support**: Guaranteed response times
- **Private Slack Channel**: Direct access to engineering team
- **Custom Integration**: Assistance with complex integrations

---

**Next Steps**: Choose a specific API section from the links above or explore the [interactive API documentation](https://api.kubenexus.yourdomain.com/docs). 