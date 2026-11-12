# 🎵 Alexa YouTube Music Bridge (Self-Hosted on VPS)

A fast, lightweight, and secure Alexa skill backend to stream YouTube Music directly to your Echo devices, hosted in a Docker container on your Ubuntu ARM VPS behind Traefik or Cloudflare Tunnel.

---

## 🔒 Security Features (Zero Exposure)
- **Amazon Signature Verification:** Validates Amazon's cryptographic PKI certificate and RSA signature on every request (`VERIFY_ALEXA_SIGNATURE=true`).
- **Skill ID Locking:** Only requests from your private `ALEXA_SKILL_ID` are processed; all others are rejected with HTTP 403.
- **HMAC Audio Tokens:** Audio URLs are signed with an expiring HMAC token (`STREAM_SECRET`). No public hotlinking or unauthorized stream access.
- **Zero API Keys Exposed:** Uses public YouTube Music endpoints. Personal cookies (optional) stay strictly inside your VPS container volume.

---

## 📁 Project Structure

```
alexa-ytm/
├── app.py                  # Single-file FastAPI backend (Alexa handlers + audio proxy)
├── requirements.txt        # Minimal Python dependencies
├── Dockerfile              # ARM64-ready Python 3.11 + ffmpeg image
├── docker-compose.yml      # Traefik-ready container config
├── .env.example            # Environment template
├── interaction_model.json  # Alexa Developer Console model
└── README.md               # Setup guide
```

---

## 🚀 Step 1: Deploy on Your VPS

1. **Clone or copy this folder to your VPS:**
   ```bash
   scp -r ./alexa-ytm user@your-vps:/opt/alexa-ytm
   cd /opt/alexa-ytm
   ```

2. **Configure `.env`:**
   ```bash
   cp .env.example .env
   nano .env
   ```
   - `DOMAIN`: Your public subdomain (e.g. `ytm.yourdomain.com`) pointing to your VPS IP in DNS.
   - `STREAM_SECRET`: Run `openssl rand -hex 16` to generate a 32-character secret.
   - `TRAEFIK_NETWORK`: Name of your existing Docker network where Traefik runs (check with `docker network ls`).
   - `TRAEFIK_CERT_RESOLVER`: Name of your Let's Encrypt resolver from `traefik.yml` (e.g. `letsencrypt`).
   - *(Leave `ALEXA_SKILL_ID` blank for now; you'll add it in Step 2).*

3. **Start the container:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify Health:**
   ```bash
   curl https://ytm.yourdomain.com/health
   # Returns: {"status":"ok","service":"alexa-ytm"}
   ```

---

## 🎙️ Step 2: Create Alexa Skill (Amazon Developer Console)

1. Go to the [Alexa Developer Console](https://developer.amazon.com/alexa/console/ask) and sign in with the **same Amazon account** used on your Echo devices.
2. Click **Create Skill**:
   - **Skill Name:** `YouTube Music`
   - **Primary locale:** Choose your device language (e.g., `English (US)` or `English (IN)`)
   - **Experience / Model:** `Custom`
   - **Hosting service:** `Provision your own`
3. Click **Create Skill**, then select the **Start from Scratch** template.
4. **Enable AudioPlayer Interface:**
   - On the left sidebar, click **Interfaces**.
   - Toggle **AudioPlayer** ON.
   - Click **Save Interfaces**.
5. **Import Interaction Model:**
   - Under **Interaction Model** on the left, click **JSON Editor**.
   - Copy the entire contents of [interaction_model.json](file:///e:/Antigravity/alexa-ytm/interaction_model.json) and paste it into the editor.
   - Click **Save Model**, then click **Build Model** (takes ~30 seconds).
6. **Set Endpoint:**
   - On the left sidebar, click **Endpoint**.
   - Select **HTTPS**.
   - **Default Region:** Enter `https://ytm.yourdomain.com/alexa`
   - **SSL Certificate Type:** Select:
     `My development endpoint is a sub-domain of a domain that has a wildcard certificate from a certificate authority`
     *(or "My development endpoint has a certificate from a trusted certificate authority" if using standard Let's Encrypt).*
   - Click **Save Endpoints**.
7. **Copy Skill ID into `.env`:**
   - Copy the Skill ID at the top (e.g., `amzn1.ask.skill.xxxx-xxxx...`).
   - On your VPS, update `ALEXA_SKILL_ID` in `.env` and run `docker compose up -d`.

---

## 🧪 Step 3: Test on Your Echo Device

1. In the Alexa Developer Console, click the **Test** tab at the top.
2. Change **Skill testing is enabled in:** from *Off* to **Development**.
3. Now the skill is automatically active on every physical Echo device linked to your Amazon account!
4. Try talking to your Echo:
   - *"Alexa, ask YouTube Music to play Blinding Lights"*
   - *"Alexa, ask YouTube Music to play Hans Zimmer"*
   - *"Alexa, pause"* / *"Alexa, resume"*
   - *"Alexa, next"* (skips to the next recommended YouTube Music radio track)

---

## 🎧 Optional: Enable Personal Liked Songs & Playlists

To let Alexa play your personal liked songs:

1. On your desktop, open Chrome and log in to [music.youtube.com](https://music.youtube.com).
2. Open DevTools (F12) → Network tab.
3. Refresh the page, click on any `browse` or `next` request, copy the request headers.
4. Use `ytmusicapi` to create `browser.json`:
   ```bash
   pip install ytmusicapi
   ytmusicapi oauth   # or ytmusicapi browser
   ```
5. Place the generated `browser.json` into `/opt/alexa-ytm/browser.json` on your VPS and restart the container:
   ```bash
   docker compose restart
   ```
6. Now you can say:
   - *"Alexa, ask YouTube Music to play my liked songs"*

