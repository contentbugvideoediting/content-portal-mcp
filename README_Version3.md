```markdown
# MCP: Make ↔ Claude ↔ OpenAI ↔ GHL ↔ Airtable (copy-paste deploy)

Important: revoke/rotate any keys you previously pasted publicly. Use NEW keys in the .env file.

Quick steps to get running locally (ngrok for public URL)

1. Create folder and copy files
   mkdir my-mcp && cd my-mcp
   (create files: server.js, package.json, Dockerfile, docker-compose.yml, .env from .env.example)

2. Create .env
   cp .env.example .env
   Edit .env and paste your NEW keys into values. Do NOT put keys into files tracked by public git.

3. Build & run with Docker Compose
   docker compose up --build -d
   # Check logs:
   docker compose logs -f

4. Test locally
   curl -X POST http://localhost:3000/webhook \
     -H "Content-Type: application/json" \
     -H "x-make-secret: <MAKE_SHARED_SECRET>" \
     -d '{"input":"Hello from test", "provider":"claude", "conversation_id":"test-1"}'

5. Expose to the internet for Make / GHL to call (temporary)
   - Install ngrok (https://ngrok.com/)
   ngrok http 3000
   - ngrok prints a public URL, e.g. https://abcd1234.ngrok.io
   - Point Make or GoHighLevel webhook to:
     https://abcd1234.ngrok.io/webhook
     Include header x-make-secret: <MAKE_SHARED_SECRET>

6. Make scenario skeleton
   - HTTP > Make a request:
     Method: POST
     URL: https://your-public-url/webhook
     Headers:
       Content-Type: application/json
       x-make-secret: <MAKE_SHARED_SECRET>
     Body (raw JSON):
     {
       "input":"Summarize the last lead conversation and propose next steps",
       "provider":"claude",
       "conversation_id":"lead-123"
     }

7. GoHighLevel webhook
   - Configure GHL to POST to https://your-public-url/webhook/ghl
   - Include header x-ghl-secret: <GHL_SHARED_SECRET>
   - The server will normalize the payload and process it.

8. Airtable setup
   - Create a Base and a table named as in AIRTABLE_TABLE (default: Conversations)
   - Fields recommended:
     - ConversationID (single line text)
     - Source (single line text)
     - Input (long text)
     - Response (long text)
     - Provider (single line text)
     - Raw (long text)
   - Use a service PAT for AIRTABLE_API_KEY with access to that base.

9. Deploy to production
   - Recommended hosts: Render, Railway, Fly, Google Cloud Run, DigitalOcean App Platform.
   - Push repo to GitHub and connect to host; add environment variables in host's secret UI.
   - Ensure HTTPS is enabled and restrict incoming traffic if possible.

Security & best practices
- Rotate any leaked keys immediately. Use new keys.
- Use HMAC signing or shared secrets and check them in the server.
- Do NOT commit .env or keys to Git.
- In production, use a proper secret manager (Render/Cloud Run secrets, AWS Secrets Manager, GitHub Secrets).
- Limit API keys' scopes and use separate keys per integration.

If you want, next I can:
- Produce a Render one-click deploy button README snippet.
- Create a prepared Make scenario step-by-step with screenshots (or an import JSON).
- Add Redis/Postgres for conversation threading.
- Harden HMAC verification and show how to sign outgoing responses.

Tell me:
- Confirm you have rotated the leaked keys (yes/no).
- Where do you want this deployed (local/ngrok, Render, Railway, Cloud Run)? I will then give the exact deploy steps for that platform.
```