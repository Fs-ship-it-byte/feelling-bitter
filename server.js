const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const BASE = 'https://pelispedia.mov';
const PS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

function buildVidUrl(imdbId, season, episode) {
    if (season && episode) {
        const epPadded = String(episode).padStart(2, '0');
        return `${BASE}/vidurl/${imdbId}-${season}x${epPadded}/`;
    }
    return `${BASE}/vidurl/${imdbId}/`;
}

// ==========================================
// 1) DESCIFRADO: Proof-of-Work + AES-CBC
// ==========================================
// El PoW (SHA-256 con dificultad N ceros al inicio) y el descifrado AES son
// operaciones estándar -- no hace falta un navegador real, se resuelven acá
// mismo en el servidor, mucho más rápido que con Puppeteer.

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

// ==========================================
// 2) RESOLUCIÓN POR SERVIDOR (VidHide, VOE, StreamWish)
// ==========================================

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
                const hlsMatch = unpacked.match(/"hls[24]"\s*:\s*"([^"]+)"/);
                if (hlsMatch) finalUrl = hlsMatch[1];
            }
        }
        if (!finalUrl) {
            const rawMatch = html.match(/"hls[24]"\s*:\s*"([^"]+)"/) || html.match(/file\s*:\s*["']([^"']+)["']/i);
            if (rawMatch) finalUrl = rawMatch[1];
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

        // ROT13
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

async function resolveByServer(servername, embedUrl) {
    const name = (servername || '').toLowerCase();
    if (name === 'vidhide') return resolveVidHide(embedUrl);
    if (name === 'streamwish') return resolveStreamWish(embedUrl);
    if (name === 'voe') return resolveVoe(embedUrl);
    console.log(`[Resolvers] Servidor sin resolver implementado: ${servername}`);
    return null;
}

// ==========================================
// 3) ENDPOINT DE STREAMING
// ==========================================

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

app.get('/stream/:type/:idWithExt', async (req, res) => {
    try {
        const id = req.params.idWithExt.replace(/\.json$/, '');
        const [imdbId, season, episode] = id.split(':');
        console.log(`--- Pedido: ${req.params.type} ${id} ---`);

        const embeds = await getDecryptedEmbeds(imdbId, season, episode);
        console.log(`Embeds descifrados: ${embeds.length} (${embeds.map(e => e.servername).join(', ')})`);

        const resolved = await Promise.all(embeds.map(async (e) => {
            const r = await resolveByServer(e.servername, e.embedUrl);
            if (!r) return null;
            return {
                name: `PelisPedia - ${e.servername}`,
                title: `${e.language} - ${e.servername}`,
                url: r.url,
                behaviorHints: { notWebReady: true, proxyHeaders: { request: r.headers } }
            };
        }));

        const streams = resolved.filter(Boolean);
        console.log(`Streams resueltos: ${streams.length}`);
        res.json({ streams });
    } catch (e) {
        console.log('Error en /stream:', e.message);
        res.json({ streams: [] });
    }
});

// --- DIAGNÓSTICO: ver los embeds descifrados sin resolverlos ---
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

app.get('/', (req, res) => {
    res.json({ status: 'online', addon: 'PelisPedia Standalone' });
});

const port = process.env.PORT || 7000;
app.listen(port, () => {
    console.log(`PelisPedia standalone escuchando en puerto ${port}`);
});
