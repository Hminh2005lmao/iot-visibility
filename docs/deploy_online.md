# Put IoT Visibility Online

This project can be exposed online for dashboard access, but keep this in mind:

- Online server can only scan networks it can reach.
- A cloud-hosted server cannot directly scan your home/school LAN behind NAT.
- For real use, run scanner near target network and optionally sync results to an online dashboard.

## Option A: Deploy to Render (quickest)

1. Push project to GitHub.
2. Create a Render Web Service from repo.
3. Render will detect `render.yaml`.
4. Set environment variable:
   - `IOT_ADMIN_API_KEY` = strong secret
5. Open deployed URL.

Recommended env vars:

- `IOT_PUBLIC_MODE=1` (forces API-key protection)
- `IOT_ADMIN_API_KEY=<your-secret>`

Health check endpoint:

- `/healthz`

## Option B: Docker on your own VPS

Build and run:

```bash
docker build -t iot-visibility .
docker run -d --name iot-visibility \
  -p 5000:5000 \
  -e IOT_PUBLIC_MODE=1 \
  -e IOT_ADMIN_API_KEY=change-this-secret \
  iot-visibility
```

Then open:

- `http://<your-server-ip>:5000`

## Security baseline before going public

1. Always set `IOT_ADMIN_API_KEY`.
2. Put app behind HTTPS reverse proxy (Nginx/Caddy/Cloudflare).
3. Restrict public access by IP if possible.
4. Keep `IOT_PUBLIC_MODE=1`.
5. Do not expose this publicly without a key.
