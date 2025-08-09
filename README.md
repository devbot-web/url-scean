# Telegram Cloudflare URL Scanner Bot

A Cloudflare Worker + Durable Object Telegram bot that scans URLs using Cloudflare's URL Scanner API and returns full reports in Markdown or HTML.

## Features
- `/scan <url>` — submit URL for scanning
- `/result <uuid>` — retrieve stored scan report
- Durable Object background polling
- HTML browser result view

## Setup

### 1. Clone & install
```bash
git clone https://github.com/devbot-web/url-scean
cd url-scean
npm install

2. Create KV namespace

wrangler kv:namespace create "SCANS_KV"

Copy the ID to wrangler.toml.

3. Deploy Durable Object

wrangler publish will register the DO automatically.

4. Add environment variables & secrets

wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put CF_API_TOKEN
wrangler secret put CF_ACCOUNT_ID

5. Deploy

npm run deploy

6. Set Telegram webhook

curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -d "url=https://<your-worker-url>/telegram"
