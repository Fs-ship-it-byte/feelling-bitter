const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://127.0.0.1:${process.env.PORT || 7000}`).replace(/\/+$/, '');
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
        timeout: 12000, responseType: 'text', transformResponse: [(d) => d],
        validateStatus: (s) => s < 500
    });
    // Antes axios devolvía un objeto cuando el sitio contestaba JSON (episodio/serie
    // que no existe, temporada 0...) y html.match reventaba con "html.match is not a function".
    const html = typeof resp.data === 'string' ? resp.data : '';
    if (!html) {
        console.log(`vidurl sin HTML válido (status ${resp.status}) para ${imdbId} ${season || ''}:${episode || ''}`);
        return [];
    }

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

// ==========================================================================
// RESOLVER HTTP COMÚN PARA STREAMWISH / VIDHIDE (y sus dominios espejo)
// Portado de laughing-dollop (src/extractors/streamhosts.js), sin dependencias nuevas.
//
// Por qué se cambió:
//  - El resolver viejo de VidHide pedía el embed con SOLO User-Agent + un Referer
//    igual al propio dominio (https://morencius.com/) y los defaults de axios
//    (Accept: application/json...). Desde cierto momento esas peticiones se
//    quedan colgadas (timeout 12s) aunque Chromium, desde la MISMA máquina, sí
//    carga la página. O sea: no es la IP, es cómo se ve la petición.
//    laughing-dollop pide con Accept/Accept-Language de navegador y Referer
//    google, y ahí VidHide sí responde.
//  - El resolver viejo de StreamWish solo buscaba "https://...m3u8" en el JS, pero
//    ahora el embed trae {hls4:"/stream/...m3u8", hls3:"https://...txt", hls2:"..."}
//    (hls4 relativo, hls3 .txt), por eso SIEMPRE caía a Chromium (~12-60 s y mucha RAM).
//  - Preferencia de link: hls4 (segmentos públicos) > hls3 > hls2 (token atado al
//    ASN de quien resolvió: en los logs aparece asn=7029, no sirve desde el celular).
// ==========================================================================
const HTTP_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
const EDGE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0';
const HLS_KEY_PREFERENCE = ['hls4', 'hls3', 'hls2'];
const HLS_LIKE = /\.(?:m3u8|txt)(?:\?|#|$)/i;
const HTTP_ATTEMPT_MS = parseInt(process.env.HTTP_ATTEMPT_MS || '8000', 10);   // tope por intento
const HEDGE_DELAY_MS = parseInt(process.env.HEDGE_DELAY_MS || '3000', 10);     // cuánto esperar antes de lanzar el siguiente perfil
const VIDHIDE_MIRRORS = (process.env.VIDHIDE_MIRRORS || 'callistanise.com').split(',').map((x) => x.trim()).filter(Boolean);
const STREAMWISH_HOSTS = ['streamwish', 'hglink', 'hgplaycdn', 'swdyu', 'cybervynx', 'dumbalag', 'niramirus', 'embedwish', 'wishfast', 'strwish', 'awish', 'flaswish', 'embedrise', 'kerapoxy', 'vibuxer', 'audinifer', 'hanerix', 'medixiru'];
const VIDHIDE_HOSTS = ['vidhide', 'vidhidepro', 'vidhideplus', 'mivalyo', 'dinisglows', 'dhtpre', 'filelions', 'callistanise', 'morencius', 'earnvids'];

// Perfiles de headers para pedir la PÁGINA del embed.
//  ld     = el de laughing-dollop (probado: funciona con morencius)
//  iframe = navegación de iframe de Edge 133, igual a la captura de la VM
const HEADER_PROFILES = {
    ld: (referer) => ({
        'User-Agent': HTTP_UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Referer': referer
    }),
    iframe: (referer) => ({
        'User-Agent': EDGE_UA,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests': '1',
        'sec-ch-ua': '"Not(A:Brand";v="99", "Microsoft Edge";v="133", "Chromium";v="133"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'Sec-Fetch-Dest': 'iframe',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Referer': referer
    })
};

function familyOf(url) {
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return null; }
    if (STREAMWISH_HOSTS.some((h) => host.includes(h))) return 'streamwish';
    if (VIDHIDE_HOSTS.some((h) => host.includes(h))) return 'vidhide';
    return null;
}

// Desempaqueta TODOS los eval(function(p,a,c,k,e,d){...}) de la página.
function baseEncode(n, a) {
    const digits = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return (n < a ? '' : baseEncode(Math.floor(n / a), a)) + digits[n % a];
}
function unpackAllEvalBlocks(html) {
    const re = /eval\(\s*function\s*\(p,a,c,k,e,[rd]\)[\s\S]*?\}\s*\(\s*'([\s\S]*?)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'([\s\S]*?)'\s*\.split\('\|'\)/g;
    let m, out = '';
    while ((m = re.exec(html)) !== null) {
        let p = m[1];
        const a = parseInt(m[2], 10);
        let c = parseInt(m[3], 10);
        const k = m[4].split('|');
        while (c--) {
            if (k[c]) p = p.replace(new RegExp('\\b' + baseEncode(c, a) + '\\b', 'g'), k[c]);
        }
        out += '\n' + p;
    }
    return out;
}

function pickPreferredHls(code, base) {
    const found = {};
    const re = /["']?\b(hls[234])["']?\s*:\s*["']([^"']+)["']/g;
    let m;
    while ((m = re.exec(code)) !== null) {
        if (!found[m[1]]) found[m[1]] = m[2].replace(/\\\//g, '/');
    }
    for (const key of HLS_KEY_PREFERENCE) {
        if (found[key] && HLS_LIKE.test(found[key])) return { url: makeAbsoluteUrl(found[key], base), key };
    }
    return null;
}
// Respaldo para páginas con formato viejo (file:"...m3u8" o URL suelta).
function pickLegacyHls(code, base) {
    const fm = code.match(/file\s*:\s*["']([^"']+\.(?:m3u8|txt)[^"']*?)["']/i);
    if (fm) return { url: makeAbsoluteUrl(fm[1].replace(/\\\//g, '/'), base), key: 'file' };
    const am = code.match(/(https?:\/\/[^"'\s\\]+\.m3u8[^"'\s\\]*)/i);
    if (am) return { url: am[1], key: 'url' };
    return null;
}

// Saltos client-side hacia un dominio "mutante" (streamwish.to/e/ID -> otro.com/e/ID).
function findMutantRedirect(html, base) {
    const patterns = [
        /window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/i,
        /location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)/i,
        /<meta[^>]+http-equiv\s*=\s*['"]refresh['"][^>]+content\s*=\s*['"][^'">\s]+url=([^'">\s]+)/i,
        /<iframe[^>]+src\s*=\s*['"]([^'"]+\/(?:e|embed)\/[a-zA-Z0-9]+[^'"]*)['"]/i
    ];
    for (const re of patterns) {
        const m = html.match(re);
        if (m && m[1]) return makeAbsoluteUrl(m[1], base);
    }
    return null;
}

// Headers con los que el navegador pediría el master (lo que mandamos al CDN
// y, vía token del proxy liviano, lo que usa nuestro server para bajar playlists):
// Origin = origen de la PÁGINA del embed; Referer = la página si el master es del
// mismo origen, o su origen + "/" si es cross-origin (así se ve en la captura).
function browserLikeHeaders(masterUrl, pageUrl, ua) {
    const h = { 'User-Agent': ua };
    try {
        const po = new URL(pageUrl).origin;
        const mo = new URL(masterUrl).origin;
        h.Referer = mo === po ? pageUrl.split('#')[0] : po + '/';
        h.Origin = po;
    } catch (e) { h.Referer = pageUrl; }
    return h;
}

async function fetchPage(url, headers, ms, signal) {
    const r = await axios.get(url, {
        headers, timeout: ms, signal, responseType: 'text', transformResponse: [(d) => d],
        maxRedirects: 5, validateStatus: (s) => s >= 200 && s < 400
    });
    const finalUrl = (r.request && r.request.res && r.request.res.responseUrl) || url;
    return { html: typeof r.data === 'string' ? r.data : '', finalUrl };
}

// Un intento completo (con hasta 4 saltos de redirección client-side) con un perfil de headers.
async function httpAttempt(startUrl, profile, firstReferer, signal, ms) {
    const mk = HEADER_PROFILES[profile];
    const visited = new Set();
    let currentUrl = startUrl;
    let referer = firstReferer;
    for (let hop = 0; hop < 4; hop++) {
        if (visited.has(currentUrl)) break;
        visited.add(currentUrl);
        const headers = mk(referer);
        const { html, finalUrl } = await fetchPage(currentUrl, headers, ms, signal);
        visited.add(finalUrl);
        const origin = new URL(finalUrl).origin;
        const code = `${unpackAllEvalBlocks(html)}\n${html}`;
        const picked = pickPreferredHls(code, origin) || pickLegacyHls(code, origin);
        if (picked) return { url: picked.url, key: picked.key, headers: browserLikeHeaders(picked.url, finalUrl, headers['User-Agent']) };
        const next = findMutantRedirect(html, origin);
        if (!next || visited.has(next)) return null;
        currentUrl = next;
        referer = origin + '/';
    }
    return null;
}

// Camino HTTP con "hedging": arranca con el perfil de laughing-dollop; si en
// HEDGE_DELAY_MS no hubo respuesta, lanza en paralelo el perfil de navegador real
// (Edge 133) y, para VidHide, el mismo archivo en un dominio espejo. Gana el primero
// que devuelve link; los demás se cancelan. Tope duro: HTTP_ATTEMPT_MS por intento.
function resolveViaHttp(embedUrl) {
    const attempts = [
        { name: 'ld', url: embedUrl, profile: 'ld', referer: 'https://www.google.com/', delay: 0 },
        { name: 'iframe', url: embedUrl, profile: 'iframe', referer: BASE + '/', delay: HEDGE_DELAY_MS }
    ];
    if (familyOf(embedUrl) === 'vidhide') {
        let host = '', id = null;
        try {
            const u = new URL(embedUrl);
            host = u.hostname;
            const m = u.pathname.match(/\/(?:embed|e|v)\/([A-Za-z0-9]+)/);
            if (m) id = m[1];
        } catch (e) { /* noop */ }
        if (id) {
            for (const mirror of VIDHIDE_MIRRORS) {
                if (host.includes(mirror)) continue;
                attempts.push({ name: 'mirror:' + mirror, url: `https://${mirror}/embed/${id}`, profile: 'ld', referer: 'https://filelions.to/', delay: HEDGE_DELAY_MS });
            }
        }
    }

    return new Promise((resolve) => {
        const t0 = Date.now();
        const timers = [];
        const ctrls = [];
        let pending = attempts.length;
        let settled = false;
        const settle = (v) => {
            if (settled) return;
            settled = true;
            timers.forEach(clearTimeout);
            ctrls.forEach((c) => { try { c.abort(); } catch (e) { /* noop */ } });
            resolve(v);
        };
        for (const a of attempts) {
            timers.push(setTimeout(async () => {
                if (settled) return;
                const ac = new AbortController();
                ctrls.push(ac);
                const kill = setTimeout(() => ac.abort(), HTTP_ATTEMPT_MS);
                try {
                    const r = await httpAttempt(a.url, a.profile, a.referer, ac.signal, HTTP_ATTEMPT_MS);
                    if (r) {
                        console.log(`[http:${a.name}] OK en ${Date.now() - t0}ms [${r.key}] ${embedUrl}`);
                        settle({ url: r.url, headers: r.headers, via: 'http:' + a.name });
                        return;
                    }
                    if (!settled) console.log(`[http:${a.name}] la página no trae link (${Date.now() - t0}ms) ${a.url}`);
                } catch (e) {
                    if (!settled) {
                        const why = (e.code === 'ERR_CANCELED' || /canceled|timeout/i.test(e.message || '')) ? `sin respuesta en ${HTTP_ATTEMPT_MS}ms` : e.message;
                        console.log(`[http:${a.name}] falló (${Date.now() - t0}ms): ${why} -- ${a.url}`);
                    }
                } finally {
                    clearTimeout(kill);
                    if (--pending === 0) settle(null);
                }
            }, a.delay));
        }
    });
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
        protocolTimeout: 30000, // sin esto un Chromium colgado bloqueaba minutos
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
    };
    if (process.env.PUPPETEER_EXECUTABLE_PATH) launchOpts.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
    _browserInstance = await puppeteer.launch(launchOpts);
    return _browserInstance;
}

async function resolveViaBrowserInner(embedUrl, timeoutMs) {
    timeoutMs = timeoutMs || BROWSER_TIMEOUT_MS;
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
        if (/timed out|Target closed|Connection closed|Protocol error|Failed to launch|Could not find/i.test(e.message || '')) {
            try { if (_browserInstance) await _browserInstance.close(); } catch (_e) { /* noop */ }
            _browserInstance = null;
            if (/Failed to launch|Could not find|WS endpoint/i.test(e.message || '')) {
                _brokenUntil = Date.now() + 5 * 60 * 1000;
                console.log('[Puppeteer] Chromium no arranca (¿poca RAM?), se desactiva el camino con navegador por 5 min');
            }
        }
        return null;
    } finally {
        if (browser && onTargetCreated) { try { browser.off('targetcreated', onTargetCreated); } catch (e) {} }
        if (page) { try { await page.close(); } catch (e) {} }
    }
}

// Chromium: UNA página a la vez y máximo BROWSER_QUEUE_MAX en cola. Antes un solo
// pedido de película abría hasta 6 páginas a la vez (3 streamwish + 3 vidhide); en
// una instancia chica de Render eso agota la RAM (en el log: "Timed out after 30000 ms
// while waiting for the WS endpoint" y el server reiniciándose una y otra vez).
const BROWSER_TIMEOUT_MS = parseInt(process.env.BROWSER_TIMEOUT_MS || '20000', 10);
const BROWSER_QUEUE_MAX = parseInt(process.env.BROWSER_QUEUE_MAX || '2', 10);
let _brokenUntil = 0;
let _bq = Promise.resolve();
let _bPending = 0;
function resolveViaBrowser(embedUrl, timeoutMs) {
    if (!puppeteer) return Promise.resolve(null);
    if (Date.now() < _brokenUntil) return Promise.resolve(null);
    if (_bPending >= BROWSER_QUEUE_MAX) {
        console.log(`[Puppeteer] cola llena (${_bPending}), se omite: ${embedUrl}`);
        return Promise.resolve(null);
    }
    _bPending++;
    const run = _bq.then(() => resolveViaBrowserInner(embedUrl, timeoutMs), () => resolveViaBrowserInner(embedUrl, timeoutMs));
    _bq = run.then(() => undefined, () => undefined);
    return run.finally(() => { _bPending--; });
}

async function resolveByServerRaw(servername, embedUrl) {
    const name = (servername || '').toLowerCase();

    if (name === 'voe') {
        // VOE deshabilitado: el checkbox de Altcha nunca terminaba de resolverse y
        // quemaba el timeout completo de Puppeteer en vano.
        return null;
    }
    if (name !== 'vidhide' && name !== 'streamwish') {
        console.log(`[Resolvers] Servidor sin resolver implementado: ${servername}`);
        return null;
    }

    const t0 = Date.now();
    const quick = await resolveViaHttp(embedUrl);
    if (quick) return quick;
    console.log(`[${name}] HTTP no encontró nada (${Date.now() - t0}ms), probando con navegador: ${embedUrl}`);
    return resolveViaBrowser(embedUrl);
}

// Caché + dedupe por embed. Los tokens duran horas, así que un resultado bueno se
// reutiliza 10 min; uno vacío 60 s (evita relanzar todo en cada reintento de Stremio).
// Si la respuesta a Stremio ya salió por el tope de tiempo, la resolución sigue en
// segundo plano y queda guardada para el reintento.
const POS_TTL_MS = 10 * 60 * 1000;
const NEG_TTL_MS = 60 * 1000;
const embedCache = new Map();
function resolveByServer(servername, embedUrl) {
    const key = `${(servername || '').toLowerCase()}|${embedUrl}`;
    const hit = embedCache.get(key);
    if (hit) {
        if (!hit.settled) return hit.p;
        if (Date.now() - hit.t < (hit.value ? POS_TTL_MS : NEG_TTL_MS)) return Promise.resolve(hit.value);
    }
    if (embedCache.size > 300) {
        for (const [k, v] of embedCache) { if (v.settled && Date.now() - v.t > POS_TTL_MS) embedCache.delete(k); }
        if (embedCache.size > 300) embedCache.clear();
    }
    const entry = { settled: false, value: null, t: Date.now() };
    entry.p = resolveByServerRaw(servername, embedUrl)
        .catch((e) => { console.log('[Resolvers] error:', e.message); return null; })
        .then((v) => { entry.settled = true; entry.value = v; entry.t = Date.now(); return v; });
    embedCache.set(key, entry);
    return entry.p;
}

function encodeProxyToken(url, headers, full) {
    const payload = { url, headers: headers || {} };
    if (full) payload.full = true;   // solo cuando aplica: los tokens normales no cambian
    return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}
function decodeProxyToken(token) {
    try { return JSON.parse(Buffer.from(token, 'base64url').toString('utf8')); }
    catch (e) { return null; }
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
function rewriteM3u8(playlistText, baseUrl, headers, full) {
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
                    const token = encodeProxyToken(abs, headers, full);
                    return `URI="${PUBLIC_URL}/hlsproxy/playlist/${token}/sub.m3u8"`;
                });
            }

            const rewritten = line.replace(/URI="([^"]+)"/i, (m, uri) => {
                const abs = makeAbsoluteUrl(uri, baseUrl.replace(/\/[^/]*$/, ''));
                const token = encodeProxyToken(abs, headers);
                return `URI="${PUBLIC_URL}/hlsproxy/segment/${token}/seg"`;
            });

            nextIsPlaylist = upper.startsWith('#EXT-X-STREAM-INF');
            return rewritten;
        }

        const absUrl = /^https?:\/\//i.test(trimmed) ? trimmed : makeAbsoluteUrl(trimmed, baseUrl.replace(/\/[^/]*$/, ''));
        const isPlaylist = nextIsPlaylist || isM3u8Url(absUrl);
        nextIsPlaylist = false;

        if (isPlaylist) {
            const token = encodeProxyToken(absUrl, headers, full);
            return `${PUBLIC_URL}/hlsproxy/playlist/${token}/sub.m3u8`;
        }
        // Con USE_PROXY=1 el segmento pasa por nuestro server, salvo los de
        // hosts de publicidad conocidos (p.ej. tiktokcdn .image): esos van
        // directo para gastar lo mínimo.
        if ((USE_PROXY || full) && !isKnownAdHost(absUrl)) {
            const token = encodeProxyToken(absUrl, headers);
            return `${PUBLIC_URL}/hlsproxy/segment/${token}/${full ? 'seg.ts' : 'seg'}`;
        }
        return absUrl;
    });
    return out.join('\n');
}

async function handleHlsPlaylistProxy(req, res) {
    const data = decodeProxyToken(req.params.token);
    if (!data) return res.status(400).send('Token inválido');
    try {
        const upstream = await axios.get(data.url, {
            headers: data.headers, timeout: 15000, responseType: 'text',
            transformResponse: [(d) => d]
        });
        const rewritten = rewriteM3u8(upstream.data, data.url, data.headers, data.full);
        res.set('Access-Control-Allow-Origin', '*');
        res.set('Content-Type', 'application/vnd.apple.mpegurl');
        res.send(rewritten);
    } catch (e) {
        res.status(502).send('No se pudo obtener el playlist: ' + e.message);
    }
}

async function handleHlsSegmentProxy(req, res) {
    const data = decodeProxyToken(req.params.token);
    if (!data) return res.status(400).send('Token inválido');
    try {
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
function buildProxyPlaylistUrl(targetUrl, headers) {
    const full = PROXY_TXT && /\.txt(\?|#|$)/i.test(targetUrl);
    const token = encodeProxyToken(targetUrl, headers, full);
    return `${PUBLIC_URL}/hlsproxy/playlist/${token}/master.m3u8`;
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
    const requestKey = `${req.params.type}:${id}`;

    if (inFlightRequests.has(requestKey)) {
        console.log(`Pedido duplicado detectado para ${requestKey} -- reusando la resolución en curso en vez de arrancar otra.`);
        try {
            const streams = await inFlightRequests.get(requestKey);
            return res.json({ streams });
        } catch (e) {
            return res.json({ streams: [] });
        }
    }

    const resultPromise = resolveStreamsFor(req.params.type, id);
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

async function resolveStreamsFor(type, id) {
    const t0 = Date.now();
    const [imdbId, season, episode] = id.split(':');
    console.log(`--- Pedido: ${type} ${id} ---`);

    const embeds = await getDecryptedEmbeds(imdbId, season, episode);
    console.log(`[${Date.now() - t0}ms] Embeds descifrados: ${embeds.length} (${embeds.map(e => e.servername).join(', ')})`);

    // Tope de respuesta: Stremio / AIOStreams descartan el addon si tarda de más
    // (en el log de Render las respuestas tardaban ~58 s). Lo que no alcance a
    // resolverse a tiempo sigue en segundo plano y queda en caché para el reintento.
    const deadlineMs = parseInt(process.env.RESPONSE_DEADLINE_MS || '18000', 10);
    let deadlineTimer;
    const deadline = new Promise((resolve) => { deadlineTimer = setTimeout(() => resolve('deadline'), deadlineMs); });
    let late = 0;
    const resolved = await Promise.all(embeds.map(async (e) => {
        const r0 = await Promise.race([resolveByServer(e.servername, e.embedUrl), deadline]);
        const r = r0 === 'deadline' ? null : r0;
        if (r0 === 'deadline') late++;
        if (!r) return null;
        console.log(`👉 [${e.servername}] (${r.via || 'browser'}) Enlace a pasar al proxy: ${r.url} | Referer=${r.headers.Referer} Origin=${r.headers.Origin}`);
        const stream = {
            name: `PelisPedia - ${e.servername}`,
            title: `${e.language} - ${e.servername}`,
            url: buildProxyPlaylistUrl(r.url, r.headers)
        };
        // Masters .txt (CDN de StreamWish en Cloudflare, CORS atado al origen del
        // embed): le pedimos a Stremio que mande Referer/Origin/UA desde el
        // cliente, sin pasar bytes por nuestro server.
        if (/\.txt(\?|#|$)/i.test(r.url) && r.headers) {
            stream.behaviorHints = { notWebReady: true, proxyHeaders: { request: { ...r.headers } } };
        }
        return stream;
    }));

    clearTimeout(deadlineTimer);
    const streams = resolved.filter(Boolean);
    console.log(`[${Date.now() - t0}ms] Streams resueltos: ${streams.length} (tiempo total de esta respuesta)${late ? ` -- ${late} siguen en curso, quedan en caché para el reintento` : ''}`);
    return streams;
}

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

app.get('/debug/http', async (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).send('Uso: /debug/http?url=<embed, p.ej. https://morencius.com/embed/XXXX>');
    res.set('Content-Type', 'text/plain');
    const out = [];
    let id = null;
    try { const m = new URL(url).pathname.match(/\/(?:embed|e|v)\/([A-Za-z0-9]+)/); if (m) id = m[1]; } catch (e) {}
    const tests = [
        // "viejo" = lo que hacía resolveVidHide antes (así se ve si el cambio de headers es lo que arregla)
        { name: 'viejo (UA + Referer propio + defaults de axios)', url, headers: { 'User-Agent': PS_UA, 'Referer': `${new URL(url).origin}/` } },
        { name: 'ld (laughing-dollop)', url, headers: HEADER_PROFILES.ld('https://www.google.com/') },
        { name: 'iframe (Edge 133)', url, headers: HEADER_PROFILES.iframe(BASE + '/') }
    ];
    if (id && familyOf(url) === 'vidhide') {
        for (const mirror of VIDHIDE_MIRRORS) tests.push({ name: 'espejo ' + mirror, url: `https://${mirror}/embed/${id}`, headers: HEADER_PROFILES.ld('https://filelions.to/') });
    }
    for (const t of tests) {
        const t0 = Date.now();
        const ac = new AbortController();
        const kill = setTimeout(() => ac.abort(), 10000);
        try {
            const r = await axios.get(t.url, { headers: t.headers, timeout: 10000, signal: ac.signal, responseType: 'text', transformResponse: [(d) => d], validateStatus: () => true, maxRedirects: 5 });
            const body = typeof r.data === 'string' ? r.data : '';
            const pageUrl = (r.request && r.request.res && r.request.res.responseUrl) || t.url;
            const picked = pickPreferredHls(`${unpackAllEvalBlocks(body)}\n${body}`, new URL(pageUrl).origin) || pickLegacyHls(body, new URL(pageUrl).origin);
            out.push(`## ${t.name}\n   ${t.url}\n   status ${r.status} en ${Date.now() - t0}ms | server=${r.headers.server || '-'} cf-mitigated=${r.headers['cf-mitigated'] || '-'} largo=${body.length}\n   link: ${picked ? `[${picked.key}] ${picked.url}` : 'NO encontrado'}` + (picked ? '' : `\n   inicio del body: ${body.slice(0, 2000).replace(/\s+/g, ' ')}`));
        } catch (e) {
            out.push(`## ${t.name}\n   ${t.url}\n   ERROR tras ${Date.now() - t0}ms: ${e.message}`);
        } finally { clearTimeout(kill); }
    }
    res.send(out.join('\n\n'));
});

app.get('/debug/resolve', async (req, res) => {
    const { server, url, force } = req.query;
    if (!server || !url) return res.status(400).send('Uso: /debug/resolve?server=streamwish&url=<embed>&force=browser (force es opcional)');
    res.set('Content-Type', 'text/plain');
    const log = [];
    const t0 = Date.now();
    try {
        let result;
        if (force === 'http') {
            log.push('Forzando solo el camino HTTP (sin navegador)...');
            result = await resolveViaHttp(url);
        } else if (force === 'browser') {
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

app.get('/debug/adcheck', async (req, res) => {
    const masterUrl = req.query.url;
    if (!masterUrl) return res.status(400).send('Falta ?url= (opcional: &referer=&origin=)');
    res.set('Content-Type', 'text/plain');
    const extraHeaders = { 'User-Agent': PS_UA };
    if (req.query.referer) extraHeaders.Referer = req.query.referer;
    if (req.query.origin) extraHeaders.Origin = req.query.origin;
    try {
        const masterResp = await axios.get(masterUrl, { headers: extraHeaders, timeout: 12000, responseType: 'text', transformResponse: [(d) => d] });
        const subLineRaw = String(masterResp.data).split(/\r?\n/).find(l => l.trim() && !l.trim().startsWith('#'));
        const subLine = makeAbsoluteUrl(subLineRaw.trim(), masterUrl.replace(/\/[^/]*$/, ''));
        const subResp = await axios.get(subLine, { headers: extraHeaders, timeout: 12000, responseType: 'text', transformResponse: [(d) => d] });
        const lines = String(subResp.data).split(/\r?\n/);
        let total = 0, ads = 0;
        const sampleReal = [];
        const sampleAds = [];
        for (const line of lines) {
            const t = line.trim();
            if (!t || t.startsWith('#')) continue;
            const abs = /^https?:\/\//i.test(t) ? t : makeAbsoluteUrl(t, subLine.replace(/\/[^/]*$/, ''));
            total++;
            if (isKnownAdHost(abs)) { ads++; if (sampleAds.length < 3) sampleAds.push(abs); }
            else { if (sampleReal.length < 3) sampleReal.push(abs); }
        }
        res.send(
            `Total de líneas de segmento en la sub-playlist: ${total}\n` +
            `Detectadas como publicidad (se filtrarían): ${ads}\n` +
            `Quedarían como reales tras el filtro: ${total - ads}\n\n` +
            `Ejemplos de "real": ${JSON.stringify(sampleReal, null, 2)}\n\n` +
            `Ejemplos de "ad" filtrado: ${JSON.stringify(sampleAds, null, 2)}`
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
