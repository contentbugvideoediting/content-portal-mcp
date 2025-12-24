# Deploy ContentBug MCP to MacStadium

## Quick Start

### 1. SSH into your MacStadium Mac
```bash
ssh user@your-macstadium-ip
```

### 2. Install Node.js (if not installed)
```bash
# Using Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install node
```

### 3. Create project directory
```bash
mkdir -p ~/contentbug-mcp
cd ~/contentbug-mcp
```

### 4. Upload files
From your local Mac, upload these files:
```bash
scp server_Production.js user@your-macstadium-ip:~/contentbug-mcp/server.js
scp package_Version3.json user@your-macstadium-ip:~/contentbug-mcp/package.json
scp env_Production.example user@your-macstadium-ip:~/contentbug-mcp/.env
```

### 5. Install dependencies
```bash
cd ~/contentbug-mcp
npm install
npm install cors  # New dependency for chat CORS
```

### 6. Edit .env with real secrets
```bash
nano .env
# Update CHAT_API_KEY, MAKE_SHARED_SECRET, GHL_SHARED_SECRET with random strings
```

### 7. Install PM2 (process manager)
```bash
npm install -g pm2
```

### 8. Start the server
```bash
pm2 start server.js --name "contentbug-mcp"
pm2 save
pm2 startup  # Follow the instructions to enable auto-start on reboot
```

### 9. Verify it's running
```bash
curl http://localhost:3000/healthz
# Should return: {"ok":true,"ts":...,"version":"production-1.0"}
```

---

## Airtable Setup

Create these tables in your Airtable base:

### ChatMessages Table
| Field | Type |
|-------|------|
| MessageID | Single line text |
| ChannelID | Single line text |
| SenderID | Single line text |
| SenderName | Single line text |
| SenderRole | Single select (client, editor, admin) |
| Content | Long text |
| MessageType | Single select (text, file, system) |
| Timestamp | Date & time |
| Read | Checkbox |

### ChatChannels Table
| Field | Type |
|-------|------|
| ChannelID | Single line text |
| Name | Single line text |
| Type | Single select (client, team, project) |
| Members | Long text |
| CreatedBy | Single line text |
| CreatedAt | Date & time |
| LastActivity | Date & time |
| UnreadCount | Number |

---

## API Endpoints

### Health Check
```
GET /healthz
```

### Chat - Send Message
```
POST /chat/messages
Headers: x-api-key: your-chat-api-key
Body: {
  "channel_id": "ch-123",
  "sender_id": "user-456",
  "sender_name": "John Doe",
  "sender_role": "client",
  "content": "Hello!",
  "message_type": "text"
}
```

### Chat - Get Messages
```
GET /chat/messages/:channel_id
Headers: x-api-key: your-chat-api-key
Query: ?since=2024-01-01T00:00:00Z&limit=50
```

### Chat - Poll for New Messages
```
GET /chat/poll/:channel_id?since=2024-01-01T00:00:00Z
Headers: x-api-key: your-chat-api-key
```

### Team Inbox (editors/admins only)
```
GET /inbox?role=admin
Headers: x-api-key: your-chat-api-key
```

---

## Update Webhooks

Once running, update your Make.com scenarios to point to:
```
https://your-macstadium-ip:3000/webhook
```

Or if you set up a domain:
```
https://api.contentbug.io/webhook
```

---

## Monitoring

### View logs
```bash
pm2 logs contentbug-mcp
```

### Restart server
```bash
pm2 restart contentbug-mcp
```

### Check status
```bash
pm2 status
```

---

## SSL Setup (Recommended)

Option 1: Cloudflare Tunnel (free, easiest)
```bash
brew install cloudflare/cloudflare/cloudflared
cloudflared tunnel login
cloudflared tunnel create contentbug
cloudflared tunnel route dns contentbug api.contentbug.io
cloudflared tunnel run contentbug
```

Option 2: Let's Encrypt + nginx (more control)
- Contact MacStadium support for guidance on their environment
