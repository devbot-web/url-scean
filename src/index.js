const TELEGRAM_API_BASE = 'https://api.telegram.org';
const TELEGRAM_TOKEN = TELEGRAM_BOT_TOKEN; // set as secret
const TELEGRAM_SEND_URL = `${TELEGRAM_API_BASE}/bot${TELEGRAM_TOKEN}/sendMessage`;
const TELEGRAM_SENDPHOTO_URL = `${TELEGRAM_API_BASE}/bot${TELEGRAM_TOKEN}/sendPhoto`;

const CF_ACCOUNT_ID = CF_ACCOUNT_ID; // environment var
const CF_BASE = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/urlscanner/v2`;

const POLL_DELAY_SECONDS = 10; // DO polls every ~10s (configurable)
const MAX_SUBMIT_PER_MINUTE = 30; // simple rate limiting per chat (basic)

/* Helper: safe fetch with timeout */
async function timeoutFetch(url, opts = {}, ms = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  opts.signal = controller.signal;
  try {
    return await fetch(url, opts);
  } finally {
    clearTimeout(id);
  }
}

/* Helper: send Telegram message with retry/backoff */
async function sendTelegram(chat_id, text, options = {}) {
  const payload = Object.assign({
    chat_id,
    text,
    parse_mode: options.parse_mode || 'Markdown',
    disable_web_page_preview: true
  }, options.extra || {});

  const url = `${TELEGRAM_API_BASE}/bot${TELEGRAM_TOKEN}/sendMessage`;
  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await timeoutFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }, 10000);
      if (res.ok) return await res.json();
      const txt = await res.text();
      console.error('Telegram send failed', res.status, txt);
    } catch (e) {
      console.error('Telegram send error', e);
    }
    // exponential backoff
    await new Promise(r => setTimeout(r, attempt * 500));
  }
  throw new Error('Failed to send message to Telegram after retries');
}

/* Input validation */
function extractUrlFromText(text) {
  // Accept /scan <url> or bare url
  if (!text) return null;
  const match = text.match(/(https?:\/\/[^\s]+)/i);
  return match ? match[1] : null;
}

function isValidUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/* ==========================
   Cloudflare URL Scanner API
   ========================== */

async function submitUrlToCF(url, options = {}) {
  const payload = Object.assign({ url }, options);
  const res = await timeoutFetch(`${CF_BASE}/scan`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  }, 15000);

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`CF submit returned ${res.status}: ${body}`);
  }
  return res.json();
}

async function getResultFromCF(uuid) {
  const res = await timeoutFetch(`${CF_BASE}/result/${uuid}`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
  }, 10000);

  if (res.status === 404) return null; // still processing
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`CF get result ${res.status}: ${body}`);
  }
  return res.json();
}

/* =======================
   Report formatters
   ======================= */

function markdownReport(report) {
  const task = report.task || {};
  const page = report.page || {};
  const verdicts = report.verdicts || {};
  const meta = report.meta || {};

  const lines = [];
  lines.push(`*URL Scan Report*`);
  lines.push(`*UUID:* \`${task.uuid || 'n/a'}\``);
  lines.push(`*Submitted URL:* ${task.url || 'n/a'}`);
  lines.push(`*Final URL:* ${page.url || 'n/a'}`);
  lines.push(`*Status:* ${task.status || 'n/a'}`);
  if (verdicts.overall) {
    lines.push(`*Malicious:* ${verdicts.overall.malicious ? 'Yes' : 'No'}`);
  }
  if (meta.processors && meta.processors.domainCategories) {
    const cats = Object.values(meta.processors.domainCategories).flat().join(', ');
    lines.push(`*Categories:* ${cats || 'None'}`);
  }
  if (report.lists && report.lists.domains) {
    const domains = report.lists.domains.slice(0,8).map(d => (d.hostname || d)).join(', ');
    lines.push(`*Domains contacted:* ${domains || 'None'}`);
  }
  lines.push(`\n_To view full JSON or screenshots, open the result page._`);
  return lines.join('\n');
}

function htmlReport(report) {
  // Simple styled HTML
  const md = markdownReport(report);
  const html = md
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*([^*]+)\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>');
  return `<!doctype html>
  <html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>URL Scan Report</title>
    <style>
      body { font-family: Inter, Roboto, system-ui, -apple-system, sans-serif; padding:20px; color:#0b1220; background:#f7fafc; }
      .card { background:white; border-radius:12px; padding:18px; box-shadow: 0 6px 24px rgba(8,12,20,0.06); max-width:900px; margin:auto; }
      pre { background:#0b1220; color:#fff; padding:12px; border-radius:8px; overflow:auto; }
      h1 { margin-top:0; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>URL Scan Report</h1>
      <div>${html}</div>
    </div>
  </body>
  </html>`;
}

/* =========================
   Durable Object (Poller)
   =========================
   Responsibilities:
   - Accept "start" messages for a scan uuid and chat_id
   - Periodically check Cloudflare result endpoint
   - When finished, store JSON into KV and notify Telegram
*/

export class ScanPollDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    // keep in-memory timers only while DO stays alive; robust behavior uses alarms
  }

  async fetch(request) {
    // support incoming POST messages (to start polling) or GET status
    if (request.method === 'POST') {
      const data = await request.json();
      if (data.type === 'start') {
        // store metadata and begin periodic alarm
        const { uuid, chat_id, submitted_url } = data;
        await this.state.storage.put(uuid, { uuid, chat_id, submitted_url, status: 'queued', createdAt: Date.now() });
        // set alarm to trigger immediately
        await this.state.storage.put('nextRun', Date.now());
        await this.state.storage.setAlarm(Date.now() + 1000); // in 1s
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response('bad request', { status: 400 });
    }

    // GET /status?uuid=...
    if (request.method === 'GET') {
      const url = new URL(request.url);
      const uuid = url.searchParams.get('uuid');
      if (!uuid) return new Response('missing uuid', { status: 400 });
      const meta = await this.state.storage.get(uuid);
      return new Response(JSON.stringify(meta || {}), { status: 200, headers: {'Content-Type': 'application/json'} });
    }
    return new Response('ok');
  }

  // Alarm handler: Cloudflare invokes "alarm" for durable objects via `alarm()` method.
  async alarm() {
    // iterate stored uuids and poll them. For simplicity we track a small set
    const list = [];
    const iter = this.state.storage.list({ prefix: '', limit: 1000 });
    for await (const { key, value } of iter) {
      // keys: uuid or 'nextRun' or metadata—filter
      if (key === 'nextRun') continue;
      if (value && value.status && value.status !== 'finished' && value.status !== 'failed') {
        list.push({ key, value });
      }
    }

    for (const item of list) {
      const uuid = item.key;
      try {
        const res = await fetch(`${CF_BASE}/result/${uuid}`, {
          headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
        });
        if (res.status === 404) {
          // still processing; continue
          continue;
        }
        if (!res.ok) {
          console.error('CF result error', res.status, await res.text());
          continue;
        }
        const json = await res.json();
        // save to global KV
        await SCANS_KV.put(uuid, JSON.stringify(json), { expirationTtl: 60 * 60 * 24 * 365 }); // keep up to 12 months
        // update DO storage meta
        const meta = Object.assign({}, item.value, { status: 'finished', finishedAt: Date.now() });
        await this.state.storage.put(uuid, meta);
        // notify telegram
        try {
          const chat_id = meta.chat_id;
          const md = markdownReport(json);
          await sendTelegram(chat_id, `Scan finished for \`${meta.submitted_url}\`\n\n${md}`, { parse_mode: 'Markdown' });
        } catch (e) {
          console.error('notify tg error', e);
        }
      } catch (e) {
        console.error('poll error', e);
      }
    }

    // schedule next check
    const next = Date.now() + (POLL_DELAY_SECONDS * 1000);
    await this.state.storage.put('nextRun', next);
    await this.state.storage.setAlarm(next);
  }
}

/* ======================
   Main Worker HTTP layer
   ====================== */

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);

  // Root - simple health
  if (request.method === 'GET' && url.pathname === '/') {
    return new Response('Telegram Cloudflare URL Scanner Bot — Ready', { status: 200 });
  }

  // Telegram webhook receiver
  if (request.method === 'POST' && url.pathname === '/telegram') {
    try {
      const payload = await request.json();
      // Basic routing for messages only
      const message = payload.message || payload.edited_message || null;
      if (!message) return new Response('no message', { status: 200 });

      const chat_id = message.chat.id;
      const text = message.text?.trim() || '';

      // Basic anti-abuse: record last submission time per chat in KV
      const rateKey = `rate:${chat_id}`;
      const last = await SCANS_KV.get(rateKey);
      if (last) {
        // parse timestamp
        const dt = Number(last);
        if (Date.now() - dt < 60000 && text.startsWith('/scan')) {
          await sendTelegram(chat_id, 'You are submitting scans too quickly. Please wait a moment.');
          return new Response('ok', { status: 200 });
        }
      }

      if (text.startsWith('/start')) {
        const msg = `Welcome! I scan URLs using Cloudflare URL Scanner.\n\nCommands:\n/scan <url> - Submit a URL for scanning\n/result <scan_uuid> - Get the latest report\n\nExample: /scan https://example.com`;
        await sendTelegram(chat_id, msg, { parse_mode: 'Markdown' });
        return new Response('ok', { status: 200 });
      }

      if (text.startsWith('/scan')) {
        const urlFound = extractUrlFromText(text);
        if (!urlFound || !isValidUrl(urlFound)) {
          await sendTelegram(chat_id, 'Please provide a valid http/https URL. Example: `/scan https://example.com`', { parse_mode: 'Markdown' });
          return new Response('ok', { status: 200 });
        }

        // record rate-limit timestamp
        await SCANS_KV.put(rateKey, String(Date.now()), { expirationTtl: 60 }); // allow one per minute by default

        // Submit to Cloudflare
        let submitResp;
        try {
          submitResp = await submitUrlToCF(urlFound, { visibility: 'Unlisted', screenshotsResolutions: ['desktop'] });
        } catch (e) {
          console.error('submit error', e);
          await sendTelegram(chat_id, `Failed to submit to Cloudflare: ${e.message}`);
          return new Response('ok', { status: 200 });
        }

        const uuid = submitResp.uuid;
        // store preliminary record in KV
        const metadata = { uuid, chat_id, submitted_url: urlFound, status: 'queued', submittedAt: Date.now() };
        await SCANS_KV.put(uuid, JSON.stringify({ meta: metadata }), { expirationTtl: 60 * 60 * 24 * 365 });

        // start durable object polling
        // route to DO: use a stable DO id per-account (we can generate deterministic id using name "global-poller")
        const id = SCAN_POLL_DO.idFromName('global-poller'); // shared poller
        const stub = SCAN_POLL_DO.get(id);
        try {
          await stub.fetch('/internal', {
            method: 'POST',
            body: JSON.stringify({ type: 'start', uuid, chat_id, submitted_url: urlFound }),
            headers: { 'Content-Type': 'application/json' }
          });
        } catch (e) {
          console.error('DO start error', e);
        }

        // Respond to user quickly
        const resultLink = `${new URL(request.url).origin}/result/${uuid}`;
        await sendTelegram(chat_id, `Scan submitted successfully.\nUUID: \`${uuid}\`\nYou will be notified when it's done. You can also view the result here: ${resultLink}`, { parse_mode: 'Markdown' });
        return new Response('ok', { status: 200 });
      }

      if (text.startsWith('/result')) {
        const parts = text.split(/\s+/);
        if (parts.length < 2) {
          await sendTelegram(chat_id, 'Usage: /result <scan_uuid>');
          return new Response('ok', { status: 200 });
        }
        const uuid = parts[1];
        // Try KV
        const raw = await SCANS_KV.get(uuid);
        if (!raw) {
          await sendTelegram(chat_id, `No report found for \`${uuid}\`. It may still be processing.`, { parse_mode: 'Markdown' });
          return new Response('ok', { status: 200 });
        }
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = null; }
        // If parsed.meta exists that's preliminary; try to fetch final JSON value
        if (parsed && parsed.meta && !parsed.result) {
          // try to fetch latest from CF
          const maybe = await getResultFromCF(uuid).catch(()=>null);
          if (maybe) {
            await SCANS_KV.put(uuid, JSON.stringify(maybe));
            parsed = maybe;
          }
        }
        if (parsed && parsed.task && parsed.task.uuid) {
          const md = markdownReport(parsed);
          await sendTelegram(chat_id, md, { parse_mode: 'Markdown' });
        } else {
          // fallback: return raw
          await sendTelegram(chat_id, `Report (partial):\n\`\`\`\n${raw}\n\`\`\``, { parse_mode: 'Markdown' });
        }
        return new Response('ok', { status: 200 });
      }

      // default fallback
      await sendTelegram(chat_id, 'Unknown command. Use /scan <url> or /result <scan_uuid>');
      return new Response('ok', { status: 200 });
    } catch (e) {
      console.error('telegram handler error', e);
      return new Response('internal error', { status: 500 });
    }
  }

  // Browser result viewer
  if (request.method === 'GET' && url.pathname.startsWith('/result/')) {
    const uuid = url.pathname.split('/').pop();
    if (!uuid) return new Response('missing uuid', { status: 400 });
    const raw = await SCANS_KV.get(uuid);
    if (!raw) {
      return new Response(`<pre>Scan ${uuid} not found or still processing.</pre>`, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' }});
    }
    // raw may be JSON report or {meta:...}
    try {
      const parsed = JSON.parse(raw);
      // if it's the final report (task exists with uuid)
      if (parsed && parsed.task && parsed.task.uuid) {
        return new Response(htmlReport(parsed), { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' }});
      } else {
        // preliminary meta; provide link to info and instructions
        return new Response(`<pre>Scan ${uuid} is queued or processing. Try again later.</pre>`, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' }});
      }
    } catch (e) {
      return new Response(`<pre>Invalid data for ${uuid}</pre>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8' }});
    }
  }

  return new Response('Not found', { status: 404 });
}
