# Google Drive Integration - Internal Documentation

**Version:** 2.1.0
**Last Updated:** 2024-12-23
**Status:** Production Ready

---

## Overview

The Content Bug Portal uses Google Drive for all client asset storage via a service account. This is a **set-and-forget** implementation requiring no ongoing maintenance.

---

## Required Environment Variables

```bash
# REQUIRED - Service account JSON (single line, no newlines)
GOOGLE_SERVICE_ACCOUNT_JSON={"type":"service_account","project_id":"...","private_key":"...","client_email":"..."}

# OPTIONAL - Override default root folder
GOOGLE_DRIVE_ROOT_FOLDER=131CAkK8L0cWy2BJX9o8m-h3arwFvPr5c
```

### How to Get Service Account JSON

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create or select project
3. Enable Drive API: APIs & Services → Enable APIs → Google Drive API
4. Create Service Account: IAM & Admin → Service Accounts → Create
5. Generate Key: Click service account → Keys → Add Key → JSON
6. Copy entire JSON file content (minify to single line)
7. Set as `GOOGLE_SERVICE_ACCOUNT_JSON` in Railway

---

## Folder Structure

For each client, this structure is automatically created:

```
Content Bug Clients/
  └── {Client Name} ({Airtable ID})/
      ├── Brand Assets/
      │   ├── Logos/
      │   ├── Thumbnails/
      │   └── Headshots/
      ├── Raw Uploads/
      ├── Creator Lab Recordings/
      └── Approved Exports/
```

**Important:**
- Folders are created ONCE per client
- Folder IDs are cached in memory AND saved to Airtable
- Never delete folders manually - they won't be recreated if IDs exist

---

## API Endpoints

### Check Status
```
GET /api/drive/status

Response:
{
  "available": true,
  "error": null,
  "limits": { "video": "500MB", "audio": "100MB", "image": "25MB" },
  "supportedTypes": ["video/mp4", "video/quicktime", ...]
}
```

### Initialize Client Folders
```
POST /api/drive/init-client
Body: { "clientName": "John Doe", "clientId": "recXXX" }

Response:
{
  "success": true,
  "folders": {
    "root": "folder_id",
    "raw_uploads": "folder_id",
    "brand_assets": "folder_id",
    ...
  }
}
```

### Upload File
```
POST /api/drive/upload
Body: FormData with:
  - file: (binary)
  - clientId: "recXXX"
  - clientName: "John Doe"
  - uploadType: "raw_upload" | "logo" | "thumbnail" | "headshot" | "creator_lab" | "export"
  - projectId: "recXXX" (optional)
  - customFileName: "my-file.mp4" (optional)

Response:
{
  "success": true,
  "file": {
    "id": "drive_file_id",
    "name": "filename.mp4",
    "size": 1234567,
    "mimeType": "video/mp4",
    "viewLink": "https://drive.google.com/file/d/.../view",
    "directLink": "https://drive.google.com/uc?export=download&id=...",
    "embedLink": "https://drive.google.com/file/d/.../preview"
  }
}
```

---

## Upload Types & Routing

| uploadType | Target Folder | Airtable Table | Field |
|------------|--------------|----------------|-------|
| raw_upload | Raw Uploads | Projects | Raw Footage Link |
| logo | Brand Assets/Logos | Contacts | Logo URL |
| thumbnail | Brand Assets/Thumbnails | Contacts | Thumbnail URL |
| headshot | Brand Assets/Headshots | Contacts | Headshot URL |
| creator_lab | Creator Lab Recordings | - | - |
| export | Approved Exports | Projects | Deliverable Link |

---

## Security Model

### Permissions
- **Scope:** `drive.file` (can only access files it creates)
- **File Access:** Anyone with link can view (reader)
- **No OAuth:** Service account only
- **Credentials:** Never logged, never written to disk

### Rate Limits
- 30 uploads per 15 minutes per IP
- Category-based size limits enforced

### Allowed File Types
- Video: mp4, mov, avi, webm, mkv, m4v
- Audio: mp3, wav, aac, m4a
- Image: jpg, png, gif, webp, svg

---

## Airtable Fields (Add These)

### Contacts Table
| Field Name | Type | Description |
|------------|------|-------------|
| Drive Root Folder | Text | Client's root folder ID |
| Drive Root Link | URL | Link to client folder |
| Drive Raw Uploads | Text | Raw uploads folder ID |
| Drive Brand Assets | Text | Brand assets folder ID |
| Drive Approved Exports | Text | Approved exports folder ID |
| Logo URL | URL | Uploaded logo link |
| Thumbnail URL | URL | Uploaded thumbnail link |
| Headshot URL | URL | Uploaded headshot link |

### Projects Table
| Field Name | Type | Description |
|------------|------|-------------|
| Drive File ID | Text | Uploaded file ID |
| Drive Folder ID | Text | Folder where file lives |
| Upload Timestamp | DateTime | When file was uploaded |

---

## What NOT to Touch

1. **Never modify folder structure constants** without updating all clients
2. **Never delete client folders** from Drive directly
3. **Never share service account credentials** outside Railway env
4. **Never change drive.file scope** to broader permissions
5. **Never remove rate limiting** on upload endpoints

---

## Credential Rotation (If Ever Needed)

1. Generate new service account key in Google Cloud Console
2. Update `GOOGLE_SERVICE_ACCOUNT_JSON` in Railway
3. Redeploy service
4. Delete old key from Google Cloud Console
5. Verify uploads work via `/api/drive/status`

**Note:** Existing file links remain valid - they don't depend on credentials.

---

## Troubleshooting

### Drive shows "not available"
- Check `GOOGLE_SERVICE_ACCOUNT_JSON` is set in Railway
- Verify JSON is valid (no newlines, proper escaping)
- Check service account has Drive API enabled

### Uploads fail silently
- Check `/api/drive/status` for error details
- Verify file type is in allowed list
- Check file size is within category limit

### Folder not created
- Folder already exists (check Airtable for ID)
- Service account lacks Drive API permissions
- Root folder ID is invalid

---

## Health Check

```bash
curl https://content-portal-mcp.up.railway.app/healthz
```

Expected when configured:
```json
{
  "ok": true,
  "version": "production-2.1.0",
  "drive": { "ready": true, "error": null }
}
```

---

## Long-Term Maintenance Required?

**NO.**

This integration is designed to run indefinitely without intervention as long as:
- Service account credentials remain valid
- Google Drive API remains available
- Railway env vars are preserved

---

*Document generated by Claude Code - v2.1.0*
