# API Reference

DriveClean REST API documentation. All protected endpoints require a valid session ID passed via the `x-session` header.

## Base URL

```
http://localhost:3000
```

Or your deployed URL (e.g., `https://driveclean.onrender.com`).

## Authentication Flow

### 1. Get OAuth URL

```
GET /api/auth/url
```

**Response:**
```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

Redirect the user to this URL to authorize the app.

### 2. OAuth Callback

Google redirects to:
```
GET /api/auth/callback?code=<code>&state=<state>
```

The server exchanges the code for tokens, creates a session, and redirects to:
```
/?session=<sessionId>
```

### 3. Use Session

Include the session ID in all subsequent requests:
```
x-session: <sessionId>
```

### 4. Logout

```
POST /api/auth/logout
Headers: x-session
```

**Response:**
```json
{ "ok": true }
```

---

## Endpoints

### Health

```
GET /health
```

No authentication required.

**Response:**
```json
{
  "status": "ok",
  "uptime": 123.45,
  "timestamp": "2026-05-21T05:00:00.000Z",
  "sessions": 3,
  "scans": 2
}
```

---

### Session

```
GET /api/session
Headers: x-session
```

**Response:**
```json
{
  "email": "user@gmail.com",
  "name": "User Name",
  "createdAt": "2026-05-21T04:00:00.000Z",
  "updatedAt": "2026-05-21T04:00:00.000Z"
}
```

**Errors:**
- `401` - Session missing or invalid

---

### Storage Quota

```
GET /api/storage
Headers: x-session
```

**Response:**
```json
{
  "usage": 5368709120,
  "limit": 16106127360,
  "usageInDrive": 5000000000,
  "usageInDriveTrash": 368709120
}
```

---

### Scan Latest

```
GET /api/scan/latest
Headers: x-session
```

**Response:**
```json
{
  "capturedAt": "2026-05-21T04:30:00.000Z",
  "scope": { "mode": "drive" },
  "total": 12345,
  "totalSize": 5368709120,
  "files": [...],
  "duplicates": [...],
  "duplicateGroups": [...],
  "large": [...],
  "old": [...],
  "empty": [...],
  "emptyFolders": [...],
  "hidden": [...],
  "orphan": [...],
  "shared": [...],
  "ownedByOthers": [...],
  "public": [...],
  "temporary": [...],
  "trash": [...],
  "extensions": [["pdf", 500], ["jpg", 300]],
  "mimeTypes": [["image", 800], ["application", 400]],
  "folderSizes": [{ "name": "Photos", "totalSize": 2000000000 }],
  "gmail": { "promotions": 5000, "social": 2000 },
  "gmailCapturedAt": "2026-05-21T04:25:00.000Z",
  "gmailOlderThanDays": 365,
  "photos": { "total": 1500, "videos": 200 },
  "photosCapturedAt": "2026-05-21T04:28:00.000Z"
}
```

**Errors:**
- `404` - No scan data found

---

### Scan History

```
GET /api/scan/history
Headers: x-session
```

**Response:**
```json
{
  "history": [
    {
      "sessionId": "abc-123",
      "timestamp": "2026-05-21T04:30:00.000Z",
      "total": 12345,
      "totalSize": 5368709120,
      "duplicates": 50,
      "large": 20,
      "old": 100,
      "scope": "drive"
    }
  ]
}
```

Returns up to 20 most recent scan entries.

---

### Storage Analytics

```
GET /api/storage/analytics
Headers: x-session
```

**Response:**
```json
{
  "extensionBreakdown": { "pdf": 500, "jpg": 300, "docx": 200 },
  "mimeTypeBreakdown": { "image": 800, "application": 400, "video": 100 },
  "ageDistribution": {
    "0-30d": 100,
    "30-90d": 200,
    "90-180d": 150,
    "180-365d": 300,
    "1y+": 500
  },
  "sizeDistribution": {
    "0-1MB": 800,
    "1-10MB": 300,
    "10-100MB": 100,
    "100MB-1GB": 50,
    "1GB+": 10
  },
  "cleanupSummary": {
    "totalFiles": 12345,
    "totalSize": 5368709120,
    "duplicates": 50,
    "duplicateWastedBytes": 1073741824,
    "largeFiles": 20,
    "oldFiles": 100,
    "emptyFiles": 30,
    "emptyFolders": 5,
    "publicFiles": 10,
    "sharedFiles": 50,
    "orphanFiles": 15,
    "hiddenFiles": 25,
    "temporaryFiles": 40,
    "trashFiles": 100,
    "potentialSavings": 2147483648
  }
}
```

---

### Export CSV

```
GET /api/export/csv?type=<category>
Headers: x-session
```

**Query Parameters:**
| Param | Values |
|-------|--------|
| `type` | `all`, `large`, `duplicates`, `old`, `empty`, `emptyFolders`, `hidden`, `orphan`, `shared`, `ownedByOthers`, `public`, `temporary`, `folders`, `trash` |

**Response:** CSV file download

---

### File Operations

#### Delete Files

```
POST /api/files/delete
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileIds": ["fileId1", "fileId2"]
}
```

**Response:**
```json
{
  "message": "Moved 2 files to trash.",
  "inventoryInvalidated": true,
  "results": [...],
  "successIds": ["fileId1", "fileId2"],
  "failed": [],
  "successCount": 2,
  "failureCount": 0
}
```

#### Restore Files

```
POST /api/files/restore
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileIds": ["fileId1", "fileId2"]
}
```

**Response:** Same as delete

#### Rename File

```
POST /api/files/rename
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileId": "1a2b3c",
  "newName": "new-filename.pdf"
}
```

**Response:**
```json
{
  "message": "File renamed successfully."
}
```

#### Move File

```
POST /api/files/move
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileId": "1a2b3c",
  "targetFolderId": "folderId123"
}
```

**Response:**
```json
{
  "message": "File moved successfully."
}
```

#### Fix Permissions

```
POST /api/files/permissions/fix
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileIds": ["fileId1", "fileId2"],
  "makePrivate": true
}
```

Removes `anyone` and `domain` type permissions from files.

**Response:**
```json
{
  "message": "Fixed permissions for 2 files.",
  "successIds": ["fileId1", "fileId2"],
  "failed": [],
  "successCount": 2,
  "failureCount": 0
}
```

#### Undo Delete

```
POST /api/files/undo-delete
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "fileIds": ["fileId1", "fileId2"]
}
```

Restores files deleted within the last 5 minutes.

**Response:**
```json
{
  "message": "Restored 2 files.",
  "successIds": ["fileId1", "fileId2"],
  "successCount": 2,
  "failureCount": 0
}
```

**Errors:**
- `400` - No recent deletions found or file IDs invalid

---

### Trash

#### Empty Trash

```
POST /api/trash/empty
Headers: x-session
```

Permanently deletes all items in trash.

**Response:**
```json
{
  "message": "Permanently deleted 50 items.",
  "deletedCount": 50
}
```

---

### Gmail

#### Clean Gmail

```
POST /api/gmail/clean
Headers: x-session, Content-Type: application/json
```

**Body:**
```json
{
  "category": "promotions",
  "olderThanDays": 365
}
```

**Categories:** `promotions`, `social`

**Response:**
```json
{
  "message": "Deleted 500 emails.",
  "deletedCount": 500
}
```

---

## WebSocket API

Connect to `ws://localhost:3000` (or `wss://` for HTTPS) to receive real-time scan progress.

### Messages

#### Start Drive Scan
```json
{
  "type": "startScan",
  "session": "<sessionId>",
  "scope": "optional-folder-id-or-url"
}
```

#### Start Gmail Scan
```json
{
  "type": "startGmailScan",
  "session": "<sessionId>",
  "olderThanDays": 365
}
```

#### Start Photos Scan
```json
{
  "type": "startPhotosScan",
  "session": "<sessionId>"
}
```

#### Cancel Scan
```json
{
  "type": "cancelScan",
  "jobId": "<jobId>"
}
```

### Server Events

#### Job Started
```json
{
  "type": "jobStarted",
  "jobId": "uuid"
}
```

#### Progress Update
```json
{
  "type": "update",
  "jobId": "uuid",
  "stage": "Scanning Drive",
  "progress": 45
}
```

#### Complete
```json
{
  "type": "update",
  "jobId": "uuid",
  "stage": "Complete",
  "progress": 100,
  "data": { "__triggerFetch": true }
}
```

#### Error
```json
{
  "type": "update",
  "jobId": "uuid",
  "stage": "Error",
  "error": "Error message"
}
```

---

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": "Error message description"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad request - invalid input |
| `401` | Unauthorized - missing or invalid session |
| `404` | Not found |
| `429` | Too many requests - rate limited |
| `500` | Internal server error |

---

## Rate Limiting

All endpoints are rate limited to **120 requests per minute per IP**. Exceeding the limit returns `429 Too Many Requests`.

---

## Security Headers

All responses include:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Content-Security-Policy` | Restrictive policy allowing only self-hosted resources |
