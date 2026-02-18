# deepiri-auth-service Validation Testing Checklist

## Test Instructions

Run these manual tests to verify input validation is working correctly.

### Prerequisites
```bash
npm run dev
# Service should start on http://localhost:5001
```

---

## Test 1: GET /auth/verify - Invalid Authorization Header

**Request:**
```bash
curl -X GET http://localhost:5001/auth/verify
```

**Expected Response:** 400 Bad Request
```json
{
  "success": false,
  "message": "Validation failed",
  "requestId": "xxx-xxx-xxx",
  "timestamp": "2026-02-08T...",
  "errors": [
    {
      "field": "authorization",
      "message": "Authorization header required",
      "value": null
    }
  ]
}
```

**Request with invalid JWT format:**
```bash
curl -X GET http://localhost:5001/auth/verify \
  -H "Authorization: InvalidToken"
```

**Expected Response:** 400 Bad Request with format error

---

## Test 2: POST /auth/refresh - Missing Refresh Token

**Request:**
```bash
curl -X POST http://localhost:5001/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected Response:** 400 Bad Request
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "field": "refreshToken",
      "message": "Refresh token required"
    }
  ]
}
```

---

## Test 3: POST /auth/logout - Missing Authorization Header

**Request:**
```bash
curl -X POST http://localhost:5001/auth/logout
```

**Expected Response:** 400 Bad Request

---

## Test 4: POST /oauth/authorize - Invalid Client ID

**Request:**
```bash
curl -X POST http://localhost:5001/oauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "invalid-not-uuid",
    "redirectUri": "https://example.com",
    "scopes": ["openid"],
    "responseType": "code"
  }'
```

**Expected Response:** 400 Bad Request
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    {
      "field": "clientId",
      "message": "Invalid client ID"
    }
  ]
}
```

---

## Test 5: POST /oauth/token - Invalid Grant Type

**Request:**
```bash
curl -X POST http://localhost:5001/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grantType": "invalid_grant",
    "clientId": "550e8400-e29b-41d4-a716-446655440000",
    "clientSecret": "this-is-a-very-long-client-secret-at-least-32-chars"
  }'
```

**Expected Response:** 400 Bad Request with grant type error

---

## Test 6: POST /oauth/register - Missing Client Name

**Request:**
```bash
curl -X POST http://localhost:5001/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirectUris": ["https://example.com/callback"],
    "scopes": ["openid"],
    "responseTypes": ["code"]
  }'
```

**Expected Response:** 400 Bad Request

---

## Test 7: POST /auth/login - Valid Credentials

**Request:**
```bash
curl -X POST http://localhost:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "ValidPass123!@#"
  }'
```

**Expected Response:** 200 or 401 (depending on if user exists)
- Should NOT return 400 validation error
- Should include `x-request-id` header in response

---

## Test 8: Request ID Tracking

**Check that x-request-id is in responses:**
```bash
curl -X GET http://localhost:5001/auth/verify -v
```

**Look for header in response:**
```
< x-request-id: 550e8400-e29b-41d4-a716-446655440000
```

---

## Test 9: Validation Error Logging

**Check logs:**
```bash
# Watch server logs for validation failures
# Should see entries like:
# "Validation failed" with requestId, path, method, errors array
```

---

## Test 10: CORS Origins from Environment

**Verify CORS is using environment variable:**

Create `.env.test`:
```
CORS_ORIGINS=https://example.com,https://test.com
```

Then test:
```bash
curl -X GET http://localhost:5001/auth/verify \
  -H "Origin: https://example.com"
```

Should allow request. Try with:
```bash
curl -X GET http://localhost:5001/auth/verify \
  -H "Origin: https://evil.com"
```

Should be blocked by CORS.

---

## Completion Checklist

- [ ] Test 1: GET /auth/verify rejects invalid headers
- [ ] Test 2: POST /auth/refresh requires token
- [ ] Test 3: POST /auth/logout requires auth header
- [ ] Test 4: POST /oauth/authorize validates client ID
- [ ] Test 5: POST /oauth/token validates grant type
- [ ] Test 6: POST /oauth/register requires client name
- [ ] Test 7: Valid requests don't return 400
- [ ] Test 8: All responses include x-request-id header
- [ ] Test 9: Validation failures are logged
- [ ] Test 10: CORS respects environment variable

---

## Expected Behavior Summary

✅ All 6 previously unprotected endpoints now validate input  
✅ All validation errors return 400 with consistent format  
✅ All responses include x-request-id for tracking  
✅ CORS origins configurable via environment  
✅ Input sanitized to prevent XSS/injection attacks  
✅ Logs include validation failures with request context  

---

## Debugging

If tests fail:

1. **Check server is running:** `curl http://localhost:5001/health`
2. **Verify imports:** Look for TypeScript errors in terminal
3. **Check logs:** Server logs should show validation attempts
4. **Restart server:** `npm run dev` (CTRL+C, then restart)

---

## Next Steps

After validation testing passes:

1. Run full integration tests: `npm test`
2. Check test coverage: `npm run test:coverage`
3. Commit changes: `git add . && git commit -m "step 6-7: add sanitization & validation"`
