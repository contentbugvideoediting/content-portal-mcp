# ContentBug Content Portal

## Source of Truth
**Airtable is the ONLY source of truth.** All data lives in Airtable. Railway deploys from this repo and syncs with Airtable.

## Environment

### Airtable (Primary Database)
- **Base ID:** `appIrlFuwtsxj8hly`
- **Base Name:** Content Portal
- **API Key:** See `.env` file or `AIRTABLE_API_KEY` env var

### Airtable Tables
| Table | Purpose |
|-------|---------|
| Clients | Customer records, subscriptions, payment info |
| Blueprints | Video editing style templates |
| Projects | Video project tracking & status |
| Team | Editors and admins |
| API | Service credentials storage |
| HTML | Portal HTML files (as attachments) |
| Channels | Chat/messaging channels |
| Messages | Channel messages |
| SI_Profiles | Social intelligence profiles |
| SI_Creators | Creator tracking |
| SI_Competitors | Competitor analysis |
| SI_Videos | Video analytics |
| SI_Settings | Configuration |

### Railway (Deployment)
- **Project ID:** `3cc72169-0f22-446c-abca-0a66003139f4`
- **Service:** `content-portal`
- **Live URL:** https://portalv2.contentbug.io
- **Railway URL:** https://content-portal-production.up.railway.app
- **Environment:** production

### Deploy Commands
```bash
# Deploy to Railway
npx -y @railway/cli up --service content-portal --detach

# Check status
npx -y @railway/cli status

# View logs
npx -y @railway/cli logs --service content-portal
```

### MCP Server
Only ONE MCP server: **Airtable**
Config location: `~/.claude/mcp.json`

## Project Structure
```
/portal           - All HTML files for the portal
  /admin          - Admin dashboard pages
  /client         - Client-facing pages
  /editor         - Editor dashboard pages
  /shared         - Shared components
/email-templates  - Email HTML templates
cbv2_server_minimal.js - Main Express server
```

## Key Integrations
- **Stripe:** Payment processing
- **Google Drive:** File storage (via googleapis)
- **GHL (GoHighLevel):** CRM webhooks

## Workflow
1. Make changes locally
2. Test with `npm start`
3. Deploy with `npx -y @railway/cli up --service content-portal --detach`
4. Sync HTML to Airtable HTML table when needed
