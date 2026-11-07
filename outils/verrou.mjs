#!/usr/bin/env node
// Verrou du wiki : chiffre les pages avec un code d'accès (AES-256-GCM, clé PBKDF2).
//
//   node outils/verrou.mjs ouvrir CODE   → déchiffre les pages publiées dans source/ (pour les modifier)
//   node outils/verrou.mjs fermer CODE   → chiffre source/*.html vers la racine (ce qui est publié)
//
// Le dossier source/ contient le texte en clair : il est dans .gitignore et ne doit
// JAMAIS être commité. Les images référencées en "images/..." sont intégrées dans la
// page chiffrée au moment de « fermer », elles ne sont donc pas publiées en clair.

import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SOURCE = path.join(RACINE, 'source');
const ITERATIONS = 600000;
const MARQUEUR = /<script id="verrou-donnees" type="application\/json">([\s\S]*?)<\/script>/;

const b64 = buf => Buffer.from(buf).toString('base64');
const deb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

async function cle(code, sel) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: sel, iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function pagesPubliees() {
  return fs.readdirSync(RACINE).filter(f => f.endsWith('.html'));
}

function integrerImages(html) {
  const types = { webp: 'image/webp', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml' };
  return html.replace(/(["'(])(images\/[^"')]+)(["')])/g, (m, a, chemin, b) => {
    const fichier = path.join(SOURCE, chemin);
    if (!fs.existsSync(fichier)) return m;
    const type = types[path.extname(fichier).slice(1).toLowerCase()] || 'application/octet-stream';
    return a + `data:${type};base64,` + fs.readFileSync(fichier).toString('base64') + b;
  });
}

async function fermer(code) {
  const fichiers = fs.readdirSync(SOURCE).filter(f => f.endsWith('.html'));
  if (!fichiers.length) throw new Error('Aucune page dans source/. Lance d’abord « ouvrir ».');
  // Même sel pour toutes les pages : le code tapé une fois sert pour tout le site.
  let sel;
  const existante = pagesPubliees().map(f => fs.readFileSync(path.join(RACINE, f), 'utf8').match(MARQUEUR)).find(Boolean);
  sel = existante ? deb64(JSON.parse(existante[1]).sel) : crypto.getRandomValues(new Uint8Array(16));
  const k = await cle(code, sel);
  const gabarit = fs.readFileSync(path.join(RACINE, 'outils', 'verrou.html'), 'utf8');
  for (const f of fichiers) {
    const html = integrerImages(fs.readFileSync(path.join(SOURCE, f), 'utf8'));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const chiffre = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(html));
    const donnees = JSON.stringify({ v: 1, sel: b64(sel), iv: b64(iv), it: ITERATIONS, c: b64(chiffre) });
    fs.writeFileSync(path.join(RACINE, f), gabarit.replace('__DONNEES__', () => donnees));
    console.log('chiffré :', f);
  }
}

async function ouvrir(code) {
  fs.mkdirSync(SOURCE, { recursive: true });
  for (const f of pagesPubliees()) {
    const m = fs.readFileSync(path.join(RACINE, f), 'utf8').match(MARQUEUR);
    if (!m) { console.log('ignoré (pas chiffré) :', f); continue; }
    const d = JSON.parse(m[1]);
    const k = await cle(code, deb64(d.sel));
    let clair;
    try {
      clair = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: deb64(d.iv) }, k, deb64(d.c));
    } catch { throw new Error('Code incorrect.'); }
    fs.writeFileSync(path.join(SOURCE, f), new TextDecoder().decode(clair));
    console.log('déchiffré :', 'source/' + f);
  }
}

const [action, code] = process.argv.slice(2);
if (!code || !['ouvrir', 'fermer'].includes(action)) {
  console.error('Usage : node outils/verrou.mjs ouvrir|fermer CODE');
  process.exit(1);
}
(action === 'fermer' ? fermer : ouvrir)(code).catch(e => { console.error(e.message); process.exit(1); });
