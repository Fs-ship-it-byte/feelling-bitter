const express = require('express');
const axios = require('axios');

const app = express();
const BASE = 'https://pelispedia.mov';
const PS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// PelisPedia arma el link del reproductor DIRECTO desde el IMDb ID, sin
// necesitar adivinar ni buscar el slug de la página:
//   Películas: /vidurl/{imdbId}/                  ej: /vidurl/tt8814476/
//   Series:    /vidurl/{imdbId}-{S}x{EE}/          ej: /vidurl/tt2861424-1x01/
//                                     (el episodio va con 2 dígitos)
function buildVidUrl(imdbId, season, episode) {
    if (season && episode) {
        const epPadded = String(episode).padStart(2, '0');
        return `${BASE}/vidurl/${imdbId}-${season}x${epPadded}/`;
    }
    return `${BASE}/vidurl/${imdbId}/`;
}

// --- DIAGNÓSTICO TEMPORAL: para ver exactamente qué devuelve /vidurl/ ---
// Uso: /debug/vidurl?imdb=tt8814476  o  /debug/vidurl?imdb=tt2861424&season=1&episode=1
app.get('/debug/vidurl', async (req, res) => {
    const { imdb, season, episode } = req.query;
    if (!imdb) return res.status(400).send('Falta ?imdb=ttXXXXXXX');

    const url = buildVidUrl(imdb, season, episode);
    res.set('Content-Type', 'text/plain');
    const log = [];
    log.push(`URL consultada: ${url}`);

    try {
        const resp = await axios.get(url, {
            headers: {
                'User-Agent': PS_UA,
                'Referer': BASE + '/',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            },
            timeout: 10000,
            maxRedirects: 5,
            validateStatus: () => true
        });
        log.push(`Status: ${resp.status}`);
        log.push(`Content-Type: ${resp.headers['content-type']}`);
        log.push(`Headers completos: ${JSON.stringify(resp.headers, null, 2)}`);
        log.push('');
        log.push('--- BODY (primeros 3000 caracteres) ---');
        const bodyStr = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data, null, 2);
        log.push(bodyStr.slice(0, 3000));
    } catch (e) {
        log.push(`ERROR: ${e.message}`);
        if (e.response) {
            log.push(`Status del error: ${e.response.status}`);
            log.push(`Body del error: ${JSON.stringify(e.response.data).slice(0, 1000)}`);
        }
    }

    res.send(log.join('\n'));
});
// --- FIN DIAGNÓSTICO TEMPORAL ---

app.get('/manifest.json', (req, res) => {
    res.json({
        id: 'com.pelispedia.standalone',
        version: '1.0.0',
        name: 'PelisPedia Standalone',
        description: 'Addon standalone para pelispedia.mov',
        types: ['movie', 'series'],
        catalogs: [],
        resources: ['stream'],
        idPrefixes: ['tt']
    });
});

app.get('/stream/:type/:idWithExt', async (req, res) => {
    // TODO: se completa una vez que sepamos, vía /debug/vidurl, el formato
    // real de la respuesta de /vidurl/... (JSON, HTML con iframe, redirect, etc).
    res.json({ streams: [] });
});

app.get('/', (req, res) => {
    res.json({
        status: 'online',
        addon: 'PelisPedia Standalone (en diagnóstico)',
        instruction: 'Probá /debug/vidurl?imdb=ttXXXXXXX primero.'
    });
});

const port = process.env.PORT || 7000;
app.listen(port, () => {
    console.log(`PelisPedia standalone escuchando en puerto ${port}`);
});
