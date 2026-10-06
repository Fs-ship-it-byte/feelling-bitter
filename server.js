const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');

// ---------------------------------------------------------------------------
// Configuración obligatoria del gateway. Si falta algo, el servidor NO arranca.
//   GATEWAY_SECRET     = el mismo valor que en el Worker
//   PROXY_SIGNING_KEY  = el mismo valor que en el Worker
//   PLAYLIST_BASE_URL  = https://<tu-worker>.workers.dev/hls/viper   (sin barra final)
// ---------------------------------------------------------------------------
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || '';
const PROXY_SIGNING_KEY = process.env.PROXY_SIGNING_KEY || '';
const PLAYLIST_BASE_URL = (process.env.PLAYLIST_BASE_URL || '').replace(/\/+$/, '');
{
    const problems = [];
    if (GATEWAY_SECRET.length < 16) problems.push('GATEWAY_SECRET (mínimo 16 caracteres)');
    if (PROXY_SIGNING_KEY.length < 16) problems.push('PROXY_SIGNING_KEY (mínimo 16 caracteres)');
    if (!/^https:\/\/[^/]+\/hls\/[a-z0-9_-]+$/.test(PLAYLIST_BASE_URL)) problems.push('PLAYLIST_BASE_URL (debe ser https://<gateway>/hls/<addon>, sin barra final)');
    if (problems.length) {
        console.error('Configuración inválida o incompleta: ' + problems.join(', '));
        process.exit(1);
    }
}
const ENABLE_DEBUG = process.env.ENABLE_DEBUG === '1';

const app = express();

// Backend cerrado: TODAS las rutas exigen el secreto que pone el gateway.
// Se responde 404 (no 401) para no delatar que aquí hay algo.
const GATEWAY_SECRET_HASH = crypto.createHash('sha256').update(GATEWAY_SECRET).digest();
app.use((req, res, next) => {
    const got = crypto.createHash('sha256').update(String(req.get('X-Gateway-Secret') || '')).digest();
    if (!crypto.timingSafeEqual(got, GATEWAY_SECRET_HASH)) return res.status(404).send('Not found');
    next();
});

// ---------------------------------------------------------------------------
// Protección contra SSRF: el proxy nunca conecta a localhost / IPs privadas,
// ni siquiera tras redirects o resoluciones DNS engañosas.
// ---------------------------------------------------------------------------
function isPrivateIp(ip) {
    if (net.isIPv4(ip)) {
        const [a, b] = ip.split('.').map(Number);
        return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
            (a === 100 && b >= 64 && b <= 127) || a >= 224;
    }
    if (net.isIPv6(ip)) {
        const x = ip.toLowerCase();
        if (x === '::1' || x === '::') return true;
        if (x.startsWith('fe80') || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('ff')) return true;
        const m4 = x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (m4) return isPrivateIp(m4[1]);
        const mh = x.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
        if (mh) {
            const hi = parseInt(mh[1], 16), lo = parseInt(mh[2], 16);
            return isPrivateIp(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
        }
        return false;
    }
    return true; // no es una IP válida
}
function assertPublicTarget(rawUrl) {
    let u;
    try { u = new URL(rawUrl); } catch (e) { throw new Error('URL inválida'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Protocolo no permitido');
    const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
        throw new Error('Destino no permitido');
    }
    if (net.isIP(host) && isPrivateIp(host)) throw new Error('Destino no permitido');
}
function safeLookup(hostname, options, cb) {
    dns.lookup(hostname, options, (err, address, family) => {
        if (err) return cb(err);
        const list = Array.isArray(address) ? address : [{ address, family }];
        if (list.some((a) => isPrivateIp(a.address))) return cb(new Error('Destino no permitido'));
        cb(null, address, family);
    });
}
axios.defaults.httpAgent = new http.Agent({ lookup: safeLookup });
axios.defaults.httpsAgent = new https.Agent({ lookup: safeLookup });
axios.defaults.maxRedirects = 3;
axios.defaults.beforeRedirect = (options) => {
    assertPublicTarget(`${options.protocol || 'https:'}//${options.hostname || options.host}`);
};

const BASE = 'https://pelispedia.mov';
const PS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

function buildVidUrl(imdbId, season, episode) {
    if (season && episode) {
        const epPadded = String(episode).padStart(2, '0');
        return `${BASE}/vidurl/${imdbId}-${season}x${epPadded}/`;
    }
    return `${BASE}/vidurl/${imdbId}/`;
}

function solvePow(challenge, difficulty) {
    const prefix = '0'.repeat(difficulty);
    let nonce = 0;
    while (true) {
        const hash = crypto.createHash('sha256').update(challenge + nonce).digest('hex');
        if (hash.startsWith(prefix)) return nonce;
        nonce++;
        if (nonce > 5000000) throw new Error('PoW no resuelto tras 5M intentos');
    }
}

function decryptLink(encryptedBase64, aesKeyBuffer) {
    try {
        const raw = Buffer.from(encryptedBase64, 'base64');
        const iv = raw.subarray(0, 16);
        const ciphertext = raw.subarray(16);
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKeyBuffer.subarray(0, 32), iv);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) {
        console.log('Error desencriptando link:', e.message);
        return null;
    }
}

async function getDecryptedEmbeds(imdbId, season, episode) {
    const url = buildVidUrl(imdbId, season, episode);
    const resp = await axios.get(url, {
        headers: { 'User-Agent': PS_UA, 'Referer': BASE + '/' },
        timeout: 12000
    });
    const html = resp.data;

    const challengeMatch = html.match(/POW_CHALLENGE\s*=\s*'([^']+)'/);
    const difficultyMatch = html.match(/POW_DIFFICULTY\s*=\s*(\d+)/);
    const saltMatch = html.match(/POW_SALT\s*=\s*'([^']+)'/);
    const dataLinkMatch = html.match(/let dataLink\s*=\s*(\[.*?\]);/s);

    if (!challengeMatch || !difficultyMatch || !saltMatch || !dataLinkMatch) {
        console.log('No se pudo extraer POW_CHALLENGE/POW_SALT/dataLink de la página.');
        return [];
    }

    const challenge = challengeMatch[1];
    const difficulty = parseInt(difficultyMatch[1], 10);
    const salt = saltMatch[1];
    const dataLink = JSON.parse(dataLinkMatch[1]);

    const nonce = solvePow(challenge, difficulty);
    const aesKey = crypto.createHash('sha256').update(challenge + nonce + salt).digest();

    const results = [];
    for (const file of dataLink) {
        const lang = file.video_language || 'LAT';
        for (const embed of file.sortedEmbeds || []) {
            const decrypted = decryptLink(embed.link, aesKey);
            if (decrypted) {
                results.push({ language: lang, servername: embed.servername, embedUrl: decrypted });
            }
        }
    }
    return results;
}

function unpackEvalPacker(script) {
    const match = script.match(/eval\(function\(p,a,c,k,e,[rd]\)\{.*?\}\s*\('([\s\S]*?)',\s*(\d+),\s*(\d+),\s*'([\s\S]*?)'\.split\('\|'\)/);
    if (!match) return null;
    let [, p, a, c, k] = match;
    a = parseInt(a); c = parseInt(c); k = k.split('|');
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';
    const decode = (l, s) => {
        let res = '';
        while (l > 0) { res = chars[l % s] + res; l = Math.floor(l / s); }
        return res || '0';
    };
    return p.replace(/\b\w+\b/g, (l) => {
        const s = parseInt(l, 36);
        return (s < k.length && k[s]) ? k[s] : decode(s, a);
    });
}

// El embed trae varios links (hls2 = CDN firmado con asn atado a la red que
// pidió el embed; hls4 = /stream/... en el propio dominio del embed, el que usa
// el reproductor en el navegador y cuyos segmentos son públicos). Antes se
// tomaba el PRIMERO que apareciera, y el orden cambia entre pedidos. Ahora
// se prefiere hls4 y hls2 queda solo como respaldo.
function pickVidHideHls(text) {
    const m4 = text.match(/"hls4"\s*:\s*"([^"]+)"/);
    const m2 = text.match(/"hls2"\s*:\s*"([^"]+)"/);
    const m = m4 || m2;
    return m ? m[1].replace(/\\\//g, '/') : null;
}

async function resolveVidHide(url) {
    try {
        const domain = new URL(url).hostname;
        const resp = await axios.get(url, {
            headers: { 'User-Agent': PS_UA, 'Referer': `https://${domain}/` },
            timeout: 12000
        });
        const html = resp.data;
        let finalUrl = null;

        const packedMatch = html.match(/eval\(function\(p,a,c,k,e,[rd]\)[\s\S]*?\.split\('\|'\)[^)]*\)\)/);
        if (packedMatch) {
            const unpacked = unpackEvalPacker(packedMatch[0]);
            if (unpacked) {
                const picked = pickVidHideHls(unpacked);
                if (picked) finalUrl = picked;
            }
        }
        if (!finalUrl) {
            const rawPicked = pickVidHideHls(html);
            if (rawPicked) finalUrl = rawPicked;
            else {
                const fileMatch = html.match(/file\s*:\s*["']([^"']+)["']/i);
                if (fileMatch) finalUrl = fileMatch[1];
            }
        }
        if (!finalUrl) return null;
        if (!finalUrl.startsWith('http')) finalUrl = new URL(url).origin + finalUrl;

        return {
            url: finalUrl,
            headers: { Referer: url.split('?')[0], Origin: new URL(url).origin, 'User-Agent': PS_UA }
        };
    } catch (e) {
        console.log('[VidHide] Error:', e.message);
        return null;
    }
}

async function resolveStreamWish(url) {
    try {
        const resp = await axios.get(url, {
            headers: { 'User-Agent': PS_UA, 'Referer': url },
            timeout: 12000
        });
        const html = resp.data;
        let m3u8Url = null;

        const packedMatch = html.match(/eval\(function\(p,a,c,k,e,[a-z]\)\{[\s\S]*?\}\s*\('([\s\S]+?)',\s*(\d+),\s*(\d+),\s*'([\s\S]+?)'\.split\('\|'\)/);
        if (packedMatch) {
            const unpacked = unpackEvalPacker(packedMatch[0]);
            if (unpacked) {
                const match = unpacked.match(/https?:\/\/[^"'\s]+\.m3u8[^"'\s]*/);
                if (match) m3u8Url = match[0];
            }
        }
        if (!m3u8Url) {
            const fileMatch = html.match(/file\s*:\s*["']([^"']+)["']/i);
            if (fileMatch) m3u8Url = fileMatch[1];
        }
        if (!m3u8Url) return null;

        return {
            url: m3u8Url,
            headers: { Referer: url, Origin: new URL(url).origin, 'User-Agent': PS_UA }
        };
    } catch (e) {
        console.log('[StreamWish] Error:', e.message);
        return null;
    }
}

function localAtob(input) {
    return Buffer.from(input, 'base64').toString('binary');
}

async function resolveVoe(url) {
    try {
        const resp = await axios.get(url, { headers: { 'User-Agent': PS_UA }, timeout: 12000 });
        const html = resp.data;

        const jsonMatch = html.match(/<script type="application\/json">([\s\S]*?)<\/script>/);
        if (!jsonMatch) return null;

        const parsed = JSON.parse(jsonMatch[1].trim());
        let encText = Array.isArray(parsed) ? parsed[0] : parsed;
        if (typeof encText !== 'string') return null;

        let decoded = encText.replace(/[a-zA-Z]/g, (c) => {
            const code = c.charCodeAt(0);
            const limit = c <= 'Z' ? 90 : 122;
            const shifted = code + 13;
            return String.fromCharCode(limit >= shifted ? shifted : shifted - 26);
        });
        const noise = ['@$', '^^', '~@', '%?', '*~', '!!', '#&'];
        for (const n of noise) decoded = decoded.split(n).join('');

        const b64_1 = localAtob(decoded);
        let shiftedStr = '';
        for (let j = 0; j < b64_1.length; j++) shiftedStr += String.fromCharCode(b64_1.charCodeAt(j) - 3);
        const reversed = shiftedStr.split('').reverse().join('');
        const decrypted = localAtob(reversed);
        const data = JSON.parse(decrypted);

        if (data && data.source) {
            return {
                url: data.source,
                headers: { 'User-Agent': PS_UA, Referer: url }
            };
        }
        return null;
    } catch (e) {
        console.log('[VOE] Error:', e.message);
        return null;
    }
}

let puppeteer = null;
try { puppeteer = require('puppeteer'); } catch (e) { /* opcional */ }

let _browserInstance = null;
async function getBrowser() {
    if (!puppeteer) throw new Error('puppeteer no está instalado');
    if (_browserInstance && _browserInstance.isConnected()) return _browserInstance;
    const launchOpts = {
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
    };
    if (process.env.PUPPETEER_EXECUTABLE_PATH) launchOpts.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
    _browserInstance = await puppeteer.launch(launchOpts);
    return _browserInstance;
}

async function resolveViaBrowser(embedUrl, timeoutMs) {
    timeoutMs = timeoutMs || 30000;
    if (!puppeteer) return null;

    let browser, page, onTargetCreated;
    try {
        browser = await getBrowser();
        page = await browser.newPage();
        await page.setUserAgent(PS_UA);
        await page.setRequestInterception(true);
        page.setDefaultTimeout(timeoutMs);
        page.setDefaultNavigationTimeout(timeoutMs);

        page.on('dialog', async (dialog) => { try { await dialog.dismiss(); } catch (e) {} });

        let resolved = null;
        let pageOrigin = null;
        try { pageOrigin = new URL(embedUrl).origin; } catch (e) {}
        let lastReferer = 'https://www.google.com/';

        function originFromReferer(referer) {
            if (referer) { try { return new URL(referer).origin; } catch (e) {} }
            return pageOrigin;
        }

        onTargetCreated = async (target) => {
            try {
                if (target.opener() === page.target()) {
                    const popup = await target.page();
                    if (popup) await popup.close();
                }
            } catch (e) {}
        };
        browser.on('targetcreated', onTargetCreated);

        page.on('request', (req) => {
            const url = req.url();
            const type = req.resourceType();
            const urlLower = url.toLowerCase();
            const AD_KEYWORDS = ['/ads/', 'vast', 'vpaid', 'popads', 'popcash', 'pop.', 'tracker', 'analytics', 'doubleclick', 'adservice', 'adsystem'];
            if (AD_KEYWORDS.some((kw) => urlLower.includes(kw))) { req.abort(); return; }
            if (type === 'image' || type === 'font') { req.abort(); return; }
            if (!resolved && type !== 'document' && (/\.m3u8(\?|$)/i.test(url) || /master\.json(\?|$)/i.test(url))) {
                resolved = {
                    url,
                    headers: {
                        Referer: req.headers()['referer'] || lastReferer,
                        Origin: originFromReferer(req.headers()['referer'] || lastReferer),
                        'User-Agent': PS_UA
                    }
                };
            }
            if (!resolved && type === 'media' && /\.mp4(\?|$)/i.test(url)) {
                resolved = {
                    url,
                    headers: {
                        Referer: req.headers()['referer'] || lastReferer,
                        Origin: originFromReferer(req.headers()['referer'] || lastReferer),
                        'User-Agent': PS_UA
                    }
                };
            }
            req.continue();
        });

        page.on('response', (resp) => {
            if (resolved) return;
            try {
                const ct = resp.headers()['content-type'] || '';
                const rUrl = resp.url();
                if (/mpegurl|vnd\.apple\.mpegurl|dash\+xml/i.test(ct) || /^video\/mp4/i.test(ct)) {
                    resolved = {
                        url: rUrl,
                        headers: {
                            Referer: resp.request().headers()['referer'] || lastReferer,
                            Origin: originFromReferer(resp.request().headers()['referer'] || lastReferer),
                            'User-Agent': PS_UA
                        }
                    };
                }
            } catch (e) {}
        });

        page.on('framenavigated', (frame) => {
            if (frame === page.mainFrame()) lastReferer = frame.url();
        });

        try {
            await page.goto(embedUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs, referer: 'https://www.google.com/' });
        } catch (e) { /* seguimos igual, puede que ya haya resuelto durante la navegación */ }

        try {
            const title = await page.title();
            if (/no encontrada|not found|404/i.test(title)) return null;
        } catch (e) {}

        const viewport = page.viewport() || { width: 1280, height: 720 };
        const centerX = Math.floor(viewport.width / 2);
        const centerY = Math.floor(viewport.height / 2);

        async function tryClickEverywhere() {
            try { await page.mouse.click(centerX, centerY); } catch (e) {}
            const selectors = [
                'video', '.jw-icon-playback', '.vjs-big-play-button', '.play-button',
                '#player', '.plyr__control--overlaid', '.vjs-play-control',
                'input[type="checkbox"][id^="altcha-checkbox"]',
                '.altcha-checkbox', '[class*="altcha"] input[type="checkbox"]',
                '[id="start"]', 'img[src*="play"]', '[onclick*="play"]',
                // Botones de "saltar anuncio" (video-ads con countdown/skip)
                '[class*="skip" i]', '[id*="skip" i]', '.videoAdUiSkipButton',
                '.ytp-ad-skip-button', 'button[aria-label*="skip" i]'
            ];
            const frames = page.frames();
            for (const frame of frames) {
                try {
                    await frame.evaluate((sels) => {
                        for (const s of sels) {
                            const el = document.querySelector(s);
                            if (el) {
                                try {
                                    if (el.type === 'checkbox' && !el.checked) el.click();
                                    else el.click();
                                } catch (e) {}
                            }
                        }
                        // Botones de "Skip" que solo tienen el texto, sin clase/id reconocible
                        const candidates = document.querySelectorAll('button, div, span, a');
                        for (const el of candidates) {
                            const txt = (el.textContent || '').trim().toLowerCase();
                            if (txt === 'skip' || txt === 'skip ad' || txt === 'saltar' || txt === 'saltar anuncio') {
                                try { el.click(); } catch (e) {}
                            }
                        }
                        const video = document.querySelector('video');
                        if (video) { try { video.muted = true; video.play().catch(() => {}); } catch (e) {} }
                    }, selectors);
                } catch (e) {}
            }
        }

        // Reintentamos el click unas pocas veces, bien espaciado (cada 3s,
        // hasta 5 intentos) -- ni el loop agresivo original (cada 1.5s sobre
        // todos los frames, que consumía de más) ni un solo intento (que
        // resultó insuficiente para el checkbox de Altcha de VOE, que a
        // veces tarda en aparecer o necesita un segundo intento).
        await tryClickEverywhere();
        let clickAttempts = 1;
        const maxClickAttempts = 5;
        const clickIntervalMs = 3000;

        const start = Date.now();
        let lastClickAt = start;
        while (!resolved && Date.now() - start < timeoutMs) {
            if (clickAttempts < maxClickAttempts && Date.now() - lastClickAt > clickIntervalMs) {
                lastClickAt = Date.now();
                clickAttempts++;
                await tryClickEverywhere();
            }
            await new Promise((r) => setTimeout(r, 300));
        }

        return resolved;
    } catch (e) {
        console.log('[Puppeteer] Error:', e.message);
        return null;
    } finally {
        if (browser && onTargetCreated) { try { browser.off('targetcreated', onTargetCreated); } catch (e) {} }
        if (page) { try { await page.close(); } catch (e) {} }
    }
}

async function resolveByServer(servername, embedUrl) {
    const name = (servername || '').toLowerCase();

    if (name === 'vidhide') {
        const quick = await resolveVidHide(embedUrl);
        if (quick) return quick;
        return resolveViaBrowser(embedUrl);
    }

    if (name === 'streamwish') {
        const quick = await resolveStreamWish(embedUrl);
        if (quick) return quick;
        console.log('[StreamWish] Método rápido no encontró nada, probando con navegador...');
        return resolveViaBrowser(embedUrl);
    }

    if (name === 'voe') {
        // VOE deshabilitado: el checkbox de Altcha nunca terminaba de
        // resolverse, así que todos los pedidos quemaban el timeout
        // completo de Puppeteer (~30s) en vano -- la fuente principal del
        // consumo excesivo. Con vidhide y streamwish alcanza.
        return null;
    }

    console.log(`[Resolvers] Servidor sin resolver implementado: ${servername}`);
    return null;
}

// Token firmado: base64url(JSON) + "." + base64url(HMAC-SHA256(PROXY_SIGNING_KEY, esa parte)).
// Lleva url, headers, full (si aplica), acct (id de cuenta, lo pone el gateway) y title,
// y caduca a las 12 h. El gateway verifica la misma firma con la misma clave.
const TOKEN_TTL_SECONDS = 12 * 3600;
function signTokenBody(body) {
    return crypto.createHmac('sha256', PROXY_SIGNING_KEY).update(body).digest('base64url');
}
function encodeProxyToken(url, headers, full, meta) {
    const payload = { url, headers: headers || {}, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS };
    if (full) payload.full = true;   // solo cuando aplica
    if (meta && meta.acct) payload.acct = String(meta.acct);
    if (meta && meta.title) payload.title = String(meta.title).slice(0, 100);
    const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    return body + '.' + signTokenBody(body);
}
function decodeProxyToken(token) {
    try {
        const t = String(token);
        const i = t.lastIndexOf('.');
        if (i < 1) return null;
        const body = t.slice(0, i);
        const given = Buffer.from(t.slice(i + 1));
        const expected = Buffer.from(signTokenBody(body));
        if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
        const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (!p || typeof p.url !== 'string' || typeof p.exp !== 'number' || p.exp < Date.now() / 1000) return null;
        return p;
    } catch (e) { return null; }
}
function makeAbsoluteUrl(url, base) {
    if (!url) return null;
    if (/^https?:\/\//i.test(url)) return url;
    if (url.indexOf('//') === 0) return 'https:' + url;
    if (url.indexOf('/') === 0) {
        try { return new URL(base).origin + url; } catch (e) { return base + url; }
    }
    return base + '/' + url;
}

// ==========================================
// VALIDACIÓN DE CANDIDATOS (evita señuelos/publicidad) -- ported de bookish-tribble
// ==========================================
// A diferencia del enfoque anterior (borrar del m3u8 cualquier línea que
// "pareciera" un ad por regex de hostname), que rompía el playlist entero
// si el heurístico se equivocaba, acá SOLO se usa para decidir si un
// candidato de URL es un señuelo completo (validándolo con una muestra de
// sus segmentos) antes de aceptarlo como fuente final. Nunca se borran
// líneas de un playlist ya aceptado -- eso descuadra las duraciones/orden
// y puede tumbar el stream completo.
function isSuspiciousSegmentUrl(u) {
    try {
        const parsed = new URL(u);
        const host = parsed.hostname.toLowerCase();
        const pathname = parsed.pathname.toLowerCase();
        // Solo hosts de redes de publicidad/tracking CONOCIDAS. No filtramos
        // por extensión (.jpg/.png/etc.) -- varios CDNs de video legítimos
        // (como morencius.com, usado por PelisPedia) disfrazan sus segmentos
        // reales con extensiones de imagen para evadir bloqueadores, y ese
        // chequeo genérico terminaba marcando el 100% del contenido real
        // como "sospechoso", tumbando todos los streams.
        if (host === 'tiktokcdn.com' || host.endsWith('.tiktokcdn.com')) return true;
        if (host === 'doubleclick.net' || host.endsWith('.doubleclick.net')) return true;
        if (host === 'googlesyndication.com' || host.endsWith('.googlesyndication.com')) return true;
        if (pathname.indexOf('/ad-site-') !== -1) return true;
        return false;
    } catch (e) { return false; }
}

// ==========================================
// DETECCIÓN DE HOST DE ADS (solo hosts confirmados, sin fetch extra)
// ==========================================
// Nada de pre-validar el candidato bajándolo de nuevo: esas URLs traen
// tokens firmados de vida corta (t=...&s=...&e=...) y algunos son de un
// solo uso -- hacer una petición extra "para validar" quema el token o
// dispara un rechazo del CDN por motivos que no tienen nada que ver con
// publicidad, tumbando streams 100% legítimos (visto con morencius.com y
// acek-cdn.com). En vez de eso, se confía en lo que el resolver ya extrajo
// del sitio real, y el filtrado de ads se hace después, por SEGMENTO
// individual y solo por host confirmado como red de publicidad -- nunca
// se descarta el playlist completo por esto.
const AD_HOSTS = [/(^|\.)tiktokcdn\.com$/i, /(^|\.)doubleclick\.net$/i, /(^|\.)googlesyndication\.com$/i];
function isKnownAdHost(u) {
    try {
        const host = new URL(u).hostname.toLowerCase();
        return AD_HOSTS.some((rx) => rx.test(host)) || u.toLowerCase().indexOf('/ad-site-') !== -1;
    } catch (e) { return false; }
}

// StreamWish ahora nombra sus playlists .txt (master.txt, index-v1-a1.txt,
// iframes-v1-a1.txt) y sus segmentos .woff2. Las .txt se tratan igual que las
// .m3u8 (playlist -> proxy liviano, se reescribe); los .woff2 no son playlist,
// así que siguen el camino de cualquier segmento (directo al CDN).
function isM3u8Url(u) { return /\.(m3u8|txt)(\?|#|$)/i.test(u); }

// USE_PROXY=1 -> proxy completo (TODO pasa por nuestro server, incluidos
//   los segmentos .ts -- máxima compatibilidad, máximo gasto de banda).
// USE_PROXY sin setear (default) -> proxy liviano: el manifiesto (.m3u8,
//   texto, KB) pasa por nuestro server con los headers correctos, pero los
//   segmentos .ts (el video real, los GB) van directo al CDN sin gastar
//   banda nuestra.
const USE_PROXY = process.env.USE_PROXY === '1';

// Reescribe el playlist SIN borrar segmentos -- si viene un pre-roll de
// publicidad mezclado, el reproductor lo pasa de largo como con cualquier
// stream con ads, en vez de que nosotros rompamos el playlist entero.
// `full` (viene en el token, ver buildProxyPlaylistUrl): proxy de segmentos SOLO
// para esta cadena de playlists (las .txt de StreamWish), con los headers del
// token y con nombre .ts para que el reproductor los acepte.
function rewriteM3u8(playlistText, baseUrl, headers, full, meta) {
    const lines = playlistText.split(/\r?\n/);
    let nextIsPlaylist = false;

    const out = lines.map((line) => {
        const trimmed = line.trim();
        if (!trimmed) return line;

        if (trimmed.startsWith('#')) {
            const upper = trimmed.toUpperCase();

            if (upper.startsWith('#EXT-X-I-FRAME-STREAM-INF')) {
                return line.replace(/URI="([^"]+)"/i, (m, uri) => {
                    const abs = makeAbsoluteUrl(uri, baseUrl.replace(/\/[^/]*$/, ''));
                    const token = encodeProxyToken(abs, headers, full, meta);
                    return `URI="${PLAYLIST_BASE_URL}/playlist/${token}/sub.m3u8"`;
                });
            }

            const rewritten = line.replace(/URI="([^"]+)"/i, (m, uri) => {
                const abs = makeAbsoluteUrl(uri, baseUrl.replace(/\/[^/]*$/, ''));
                const token = encodeProxyToken(abs, headers, false, meta);
                return `URI="${PLAYLIST_BASE_URL}/segment/${token}/seg"`;
            });

            nextIsPlaylist = upper.startsWith('#EXT-X-STREAM-INF');
            return rewritten;
        }

        const absUrl = /^https?:\/\//i.test(trimmed) ? trimmed : makeAbsoluteUrl(trimmed, baseUrl.replace(/\/[^/]*$/, ''));
        const isPlaylist = nextIsPlaylist || isM3u8Url(absUrl);
        nextIsPlaylist = false;

        if (isPlaylist) {
            const token = encodeProxyToken(absUrl, headers, full, meta);
            return `${PLAYLIST_BASE_URL}/playlist/${token}/sub.m3u8`;
        }
        // Con USE_PROXY=1 el segmento pasa por nuestro server, salvo los de
        // hosts de publicidad conocidos (p.ej. tiktokcdn .image): esos van
        // directo para gastar lo mínimo.
        if ((USE_PROXY || full) && !isKnownAdHost(absUrl)) {
            const token = encodeProxyToken(absUrl, headers, false, meta);
            return `${PLAYLIST_BASE_URL}/segment/${token}/${full ? 'seg.ts' : 'seg'}`;
        }
        return absUrl;
    });
    return out.join('\n');
}

async function handleHlsPlaylistProxy(req, res) {
    const data = decodeProxyToken(req.params.token);
    if (!data) return res.status(400).send('Token inválido');
    try {
        assertPublicTarget(data.url);
        const upstream = await axios.get(data.url, {
            headers: data.headers, timeout: 15000, responseType: 'text',
            transformResponse: [(d) => d]
        });
        const rewritten = rewriteM3u8(upstream.data, data.url, data.headers, data.full, { acct: data.acct, title: data.title });
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Content-Type', 'application/vnd.apple.mpegurl');
        res.send(rewritten);
    } catch (e) {
        console.log('Playlist no disponible:', e.message);
        res.status(502).send('No se pudo obtener el playlist');
    }
}

async function handleHlsSegmentProxy(req, res) {
    const data = decodeProxyToken(req.params.token);
    if (!data) return res.status(400).send('Token inválido');
    try {
        assertPublicTarget(data.url);
        const upstream = await axios.get(data.url, {
            headers: data.headers, timeout: 20000, responseType: 'stream'
        });
        res.set('Access-Control-Allow-Origin', '*');
        if (upstream.headers['content-type']) res.set('Content-Type', upstream.headers['content-type']);
        upstream.data.pipe(res);
    } catch (e) {
        res.status(502).send('No se pudo obtener el segmento');
    }
}

// PROXY_TXT=1 (opcional, APAGADO por defecto): los streams cuyo master es .txt
// pasan también sus segmentos por el server, con headers. Sin esto, todo va
// directo al CDN y los headers los intenta mandar el cliente (ver proxyHeaders
// más abajo).
const PROXY_TXT = process.env.PROXY_TXT === '1';
function buildProxyPlaylistUrl(targetUrl, headers, meta) {
    const full = PROXY_TXT && /\.txt(\?|#|$)/i.test(targetUrl);
    const token = encodeProxyToken(targetUrl, headers, full, meta);
    return `${PLAYLIST_BASE_URL}/playlist/${token}/master.m3u8`;
}

app.get('/hlsproxy/playlist/:token/*', handleHlsPlaylistProxy);
app.get('/hlsproxy/segment/:token/*', handleHlsSegmentProxy);

app.get('/manifest.json', (req, res) => {
    res.json({
        id: 'com.pelispedia.standalone',
        version: '1.0.0',
        name: 'PelisPedia Standalone',
        description: 'Addon standalone para pelispedia.mov (vía embed69)',
        types: ['movie', 'series'],
        catalogs: [],
        resources: ['stream'],
        idPrefixes: ['tt']
    });
});

// Stremio suele reintentar automáticamente si un pedido de stream tarda
// mucho en responder -- eso dispara TODO el pipeline de nuevo (incluyendo
// otro navegador Puppeteer), duplicando el trabajo y compitiendo por los
// mismos recursos, lo cual paradójicamente hace que todo tarde AÚN MÁS. Para
// cortar eso: si llega un pedido idéntico (mismo type+id) mientras ya hay
// uno igual en curso, esperamos el MISMO resultado en vez de arrancar todo
// de nuevo desde cero.
const inFlightRequests = new Map();

app.get('/stream/:type/:idWithExt', async (req, res) => {
    const id = req.params.idWithExt.replace(/\.json$/, '');
    // X-Account-Id lo pone el gateway; va dentro de los tokens firmados.
    const acct = String(req.get('X-Account-Id') || '');
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(acct)) return res.status(400).json({ streams: [] });
    // la clave incluye la cuenta: dos cuentas nunca comparten una resolución en curso
    const requestKey = `${acct}|${req.params.type}:${id}`;

    if (inFlightRequests.has(requestKey)) {
        console.log(`Pedido duplicado detectado para ${requestKey} -- reusando la resolución en curso en vez de arrancar otra.`);
        try {
            const streams = await inFlightRequests.get(requestKey);
            return res.json({ streams });
        } catch (e) {
            return res.json({ streams: [] });
        }
    }

    const resultPromise = resolveStreamsFor(req.params.type, id, acct);
    inFlightRequests.set(requestKey, resultPromise);
    try {
        const streams = await resultPromise;
        res.json({ streams });
    } catch (e) {
        console.log('Error en /stream:', e.message);
        res.json({ streams: [] });
    } finally {
        inFlightRequests.delete(requestKey);
    }
});

async function resolveStreamsFor(type, id, acct) {
    const t0 = Date.now();
    const [imdbId, season, episode] = id.split(':');
    console.log(`--- Pedido: ${type} ${id} ---`);

    const embeds = await getDecryptedEmbeds(imdbId, season, episode);
    console.log(`[${Date.now() - t0}ms] Embeds descifrados: ${embeds.length} (${embeds.map(e => e.servername).join(', ')})`);

    const resolved = await Promise.all(embeds.map(async (e) => {
        const r = await resolveByServer(e.servername, e.embedUrl);
        if (!r) return null;
        console.log(`👉 [${e.servername}] Enlace a pasar al proxy: ${r.url} | Referer=${r.headers.Referer} Origin=${r.headers.Origin}`);
        const stream = {
            name: `PelisPedia - ${e.servername}`,
            title: `${e.language} - ${e.servername}`,
            url: buildProxyPlaylistUrl(r.url, r.headers, { acct, title: id })
        };
        // Masters .txt (CDN de StreamWish en Cloudflare, CORS atado al origen del
        // embed): le pedimos a Stremio que mande Referer/Origin/UA desde el
        // cliente, sin pasar bytes por nuestro server.
        if (/\.txt(\?|#|$)/i.test(r.url) && r.headers) {
            stream.behaviorHints = { notWebReady: true, proxyHeaders: { request: { ...r.headers } } };
        }
        return stream;
    }));

    const streams = resolved.filter(Boolean);
    console.log(`[${Date.now() - t0}ms] Streams resueltos: ${streams.length} (tiempo total de esta respuesta)`);
    return streams;
}

// Rutas de diagnóstico: apagadas por defecto. Solo existen con ENABLE_DEBUG=1
// (y, como todo el backend, siguen exigiendo el secreto del gateway).
// /debug/adcheck se eliminó: llamaba a looksLikeAdUrl, que no existe.
if (ENABLE_DEBUG) {
    app.get('/debug/browsercheck', async (req, res) => {
        res.set('Content-Type', 'text/plain');
        if (!puppeteer) return res.status(500).send('El paquete "puppeteer" no está instalado (require falló al arrancar el server).');
        try {
            const t0 = Date.now();
            const browser = await getBrowser();
            const page = await browser.newPage();
            await page.goto('https://example.com', { waitUntil: 'domcontentloaded', timeout: 15000 });
            const title = await page.title();
            await page.close();
            res.send(`OK -- Chromium arrancó y navegó en ${Date.now() - t0}ms.\nTítulo de prueba (example.com): ${title}`);
        } catch (e) {
            res.status(500).send(`ERROR al arrancar/usar Puppeteer: ${e.message}\n\nStack:\n${e.stack}`);
        }
    });

    app.get('/debug/resolve', async (req, res) => {
        const { server, url, force } = req.query;
        if (!server || !url) return res.status(400).send('Uso: /debug/resolve?server=streamwish&url=<embed>&force=browser (force es opcional)');
        res.set('Content-Type', 'text/plain');
        const log = [];
        const t0 = Date.now();
        try {
            let result;
            if (force === 'browser') {
                log.push('Forzando resolución vía navegador (saltando el método rápido)...');
                result = await resolveViaBrowser(url);
            } else {
                result = await resolveByServer(server, url);
            }
            log.push(`[${Date.now() - t0}ms] Resultado: ${result ? JSON.stringify(result, null, 2) : 'null'}`);
        } catch (e) {
            log.push(`EXCEPCIÓN: ${e.message}\n${e.stack}`);
        }
        res.send(log.join('\n'));
    });

    app.get('/debug/embeds', async (req, res) => {
        const { imdb, season, episode } = req.query;
        if (!imdb) return res.status(400).send('Falta ?imdb=ttXXXXXXX');
        res.set('Content-Type', 'text/plain');
        try {
            const embeds = await getDecryptedEmbeds(imdb, season, episode);
            res.send(JSON.stringify(embeds, null, 2));
        } catch (e) {
            res.status(500).send('Error: ' + e.message);
        }
    });

    app.get('/debug/rawfetch', async (req, res) => {
        const proxyUrl = req.query.url;
        if (!proxyUrl) return res.status(400).send('Falta ?url=<link completo de /hlsproxy/playlist/.../algo.m3u8>');
        const m = proxyUrl.match(/\/hlsproxy\/playlist\/([^/]+)\//);
        if (!m) return res.status(400).send('Esa URL no es un link de /hlsproxy/playlist/...');
        const data = decodeProxyToken(m[1]);
        if (!data) return res.status(400).send('Token inválido');

        res.set('Content-Type', 'text/plain');
        try {
            const upstream = await axios.get(data.url, {
                headers: data.headers, timeout: 12000, responseType: 'text',
                transformResponse: [(d) => d], validateStatus: () => true
            });
            res.send(
                `URL real consultada: ${data.url}\n` +
                `Headers usados: ${JSON.stringify(data.headers, null, 2)}\n` +
                `Status: ${upstream.status}\n\n` +
                `--- BODY CRUDO (sin filtrar) ---\n${upstream.data}`
            );
        } catch (e) {
            res.status(500).send('Error: ' + e.message);
        }
    });

    app.get('/debug/fullchain', async (req, res) => {
        const masterUrl = req.query.url;
        if (!masterUrl) return res.status(400).send('Falta ?url= (opcional: &referer=&origin=)');
        res.set('Content-Type', 'text/plain');
        const log = [];
        const t0 = Date.now();
        const p = (msg) => log.push(`[${Date.now() - t0}ms] ${msg}`);

        const extraHeaders = { 'User-Agent': PS_UA };
        if (req.query.referer) extraHeaders.Referer = req.query.referer;
        if (req.query.origin) extraHeaders.Origin = req.query.origin;
        p(`Headers usados: ${JSON.stringify(extraHeaders)}`);

        async function fetchText(u) {
            return axios.get(u, { timeout: 12000, responseType: 'text', transformResponse: [(d) => d], validateStatus: () => true, headers: extraHeaders });
        }
        async function fetchBinary(u) {
            return axios.get(u, { timeout: 12000, responseType: 'arraybuffer', validateStatus: () => true, headers: extraHeaders });
        }

        try {
            const masterResp = await fetchText(masterUrl);
            p(`MASTER status ${masterResp.status}, largo ${String(masterResp.data).length}`);
            if (masterResp.status !== 200) return res.send(log.join('\n') + '\n\nBody:\n' + String(masterResp.data).slice(0, 500));

            const subLineRaw = String(masterResp.data).split(/\r?\n/).find(l => l.trim() && !l.trim().startsWith('#'));
            if (!subLineRaw) return res.send(log.join('\n') + '\n\nEl master no tiene sub-playlist.');
            const subLine = makeAbsoluteUrl(subLineRaw.trim(), masterUrl.replace(/\/[^/]*$/, ''));
            p(`Sub-playlist: ${subLine}`);

            const subResp = await fetchText(subLine);
            p(`SUB-PLAYLIST status ${subResp.status}, largo ${String(subResp.data).length}`);
            if (subResp.status !== 200) return res.send(log.join('\n') + '\n\nBody:\n' + String(subResp.data).slice(0, 500));
            p('Primeros 300 chars de la sub-playlist:\n' + String(subResp.data).slice(0, 300));

            const segLineRaw = String(subResp.data).split(/\r?\n/).find(l => l.trim() && !l.trim().startsWith('#'));
            if (!segLineRaw) return res.send(log.join('\n') + '\n\nSin segmentos.');
            const segLine = makeAbsoluteUrl(segLineRaw.trim(), subLine.replace(/\/[^/]*$/, ''));
            p(`Primer segmento: ${segLine}`);

            const segResp = await fetchBinary(segLine);
            p(`SEGMENTO status ${segResp.status}, bytes: ${segResp.data ? segResp.data.byteLength : 0}`);
            res.send(log.join('\n'));
        } catch (e) {
            p('EXCEPCIÓN: ' + e.message);
            res.status(500).send(log.join('\n'));
        }
    });
}

app.get('/', (req, res) => {
    res.json({ status: 'online', addon: 'PelisPedia Standalone' });
});

const port = process.env.PORT || 7000;
app.listen(port, () => {
    console.log(`PelisPedia standalone escuchando en puerto ${port}`);
});

async function shutdown() {
    if (_browserInstance) { try { await _browserInstance.close(); } catch (e) {} }
    process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
