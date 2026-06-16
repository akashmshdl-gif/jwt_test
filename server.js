const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const dotenv = require('dotenv');
const { buildJwksFromPemEnv, resolvePath } = require('./lib/buildJwksFromPem.js');

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const JWT_ALG = process.env.JWT_ALG || 'RS384';
const JWT_KID = process.env.JWT_KID || '';
const PUBLIC_KEY_PATH = process.env.PUBLIC_KEY_PATH || '';
const JWKS_JSON_PATH = process.env.JWKS_JSON_PATH || '';
const EC_PUBLIC_KEY_PATH = process.env.EC_PUBLIC_KEY_PATH || '';
const PROVIDER_PUBLIC_KEY_PATH = process.env.PROVIDER_PUBLIC_KEY_PATH || '';
const PROVIDER_JWKS_JSON_PATH = process.env.PROVIDER_JWKS_JSON_PATH || '';
const PATIENT_PUBLIC_KEY_PATH = process.env.PATIENT_PUBLIC_KEY_PATH || '';
const PATIENT_JWKS_JSON_PATH = process.env.PATIENT_JWKS_JSON_PATH || '';
const CACHE_CONTROL =
  process.env.CACHE_CONTROL ?? 'public, max-age=3600';

async function buildJwksFromPem() {
  try {
    return await buildJwksFromPemEnv(__dirname);
  } catch (e) {
    const hint =
      e.message &&
        e.message.includes('PUBLIC_KEY_PATH not found') &&
        (!PUBLIC_KEY_PATH ||
          path.normalize(PUBLIC_KEY_PATH) ===
          path.normalize('./keys/public.pem')) &&
        !process.env.JWKS_JSON_PATH
        ? ' Run: npm run setup:dev (creates keys/public.pem for local dev only).'
        : '';
    throw new Error(`${e.message}${hint}`);
  }
}

function loadJwksFromFile() {
  const jsonPath = resolvePath(__dirname, JWKS_JSON_PATH);
  if (!jsonPath || !fs.existsSync(jsonPath)) {
    throw new Error(
      `JWKS_JSON_PATH not found or missing: ${JWKS_JSON_PATH || '(empty)'}`
    );
  }
  const raw = fs.readFileSync(jsonPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.keys)) {
    throw new Error('JWKS JSON must be an object with a "keys" array');
  }
  return parsed;
}

let cachedJwks;

async function getJwks() {
  if (cachedJwks) return cachedJwks;
  if (JWKS_JSON_PATH) {
    cachedJwks = loadJwksFromFile();
  } else {
    cachedJwks = await buildJwksFromPem();
  }
  return cachedJwks;
}

async function buildProviderJwksFromPem() {
  try {
    return await buildJwksFromPemEnv(__dirname, 'PROVIDER_');
  } catch (e) {
    const hint =
      e.message &&
        e.message.includes('PROVIDER_PUBLIC_KEY_PATH not found') &&
        !PROVIDER_PUBLIC_KEY_PATH &&
        !process.env.PROVIDER_JWKS_JSON_PATH
        ? ' Check provider keys in .env.'
        : '';
    throw new Error(`${e.message}${hint}`);
  }
}

function loadProviderJwksFromFile() {
  const jsonPath = resolvePath(__dirname, PROVIDER_JWKS_JSON_PATH);
  if (!jsonPath || !fs.existsSync(jsonPath)) {
    throw new Error(
      `PROVIDER_JWKS_JSON_PATH not found or missing: ${PROVIDER_JWKS_JSON_PATH || '(empty)'}`
    );
  }
  const raw = fs.readFileSync(jsonPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.keys)) {
    throw new Error('PROVIDER JWKS JSON must be an object with a "keys" array');
  }
  return parsed;
}

let cachedProviderJwks;

async function getProviderJwks() {
  if (cachedProviderJwks) return cachedProviderJwks;
  if (PROVIDER_JWKS_JSON_PATH) {
    cachedProviderJwks = loadProviderJwksFromFile();
  } else {
    cachedProviderJwks = await buildProviderJwksFromPem();
  }
  return cachedProviderJwks;
}

async function buildPatientJwksFromPem() {
  try {
    return await buildJwksFromPemEnv(__dirname, 'PATIENT_');
  } catch (e) {
    const hint =
      e.message &&
        e.message.includes('PATIENT_PUBLIC_KEY_PATH not found') &&
        !PATIENT_PUBLIC_KEY_PATH &&
        !process.env.PATIENT_JWKS_JSON_PATH
        ? ' Check patient keys in .env.'
        : '';
    throw new Error(`${e.message}${hint}`);
  }
}

function loadPatientJwksFromFile() {
  const jsonPath = resolvePath(__dirname, PATIENT_JWKS_JSON_PATH);
  if (!jsonPath || !fs.existsSync(jsonPath)) {
    throw new Error(
      `PATIENT_JWKS_JSON_PATH not found or missing: ${PATIENT_JWKS_JSON_PATH || '(empty)'}`
    );
  }
  const raw = fs.readFileSync(jsonPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.keys)) {
    throw new Error('PATIENT JWKS JSON must be an object with a "keys" array');
  }
  return parsed;
}

let cachedPatientJwks;

async function getPatientJwks() {
  if (cachedPatientJwks) return cachedPatientJwks;
  if (PATIENT_JWKS_JSON_PATH) {
    cachedPatientJwks = loadPatientJwksFromFile();
  } else {
    cachedPatientJwks = await buildPatientJwksFromPem();
  }
  return cachedPatientJwks;
}

const app = express();

app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const jwks = await getJwks();
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', CACHE_CONTROL);
    res.status(200).json(jwks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load JWKS' });
  }
});

app.get('/provider/.well-known/jwks.json', async (req, res) => {
  try {
    const jwks = await getProviderJwks();
    const formattedJwks = {
      ...jwks,
      keys: jwks.keys.map(key => {
        if (key.kty === 'RSA') {
          return {
            kty: 'RSA',
            kid: key.kid,
            use: 'sig',
            alg: key.alg || process.env.PROVIDER_JWT_ALG || process.env.JWT_ALG || 'RS384',
            n: key.n,
            e: key.e
          };
        }
        if (key.kty === 'EC') {
          return {
            kty: 'EC',
            kid: key.kid,
            use: 'sig',
            alg: key.alg || process.env.PROVIDER_JWT_ALG_EC || process.env.JWT_ALG_EC || 'ES384',
            crv: key.crv,
            x: key.x,
            y: key.y
          };
        }
        return key;
      })
    };
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', CACHE_CONTROL);
    res.status(200).json(formattedJwks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load Provider JWKS' });
  }
});

app.get('/patient/.well-known/jwks.json', async (req, res) => {
  try {
    const jwks = await getPatientJwks();
    const formattedJwks = {
      ...jwks,
      keys: jwks.keys.map(key => {
        if (key.kty === 'RSA') {
          return {
            kty: 'RSA',
            kid: key.kid,
            use: 'sig',
            alg: key.alg || process.env.PATIENT_JWT_ALG || process.env.JWT_ALG || 'RS384',
            n: key.n,
            e: key.e
          };
        }
        if (key.kty === 'EC') {
          return {
            kty: 'EC',
            kid: key.kid,
            use: 'sig',
            alg: key.alg || process.env.PATIENT_JWT_ALG_EC || process.env.JWT_ALG_EC || 'ES384',
            crv: key.crv,
            x: key.x,
            y: key.y
          };
        }
        return key;
      })
    };
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', CACHE_CONTROL);
    res.status(200).json(formattedJwks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load Patient JWKS' });
  }
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

async function validateConfig() {
  if (JWKS_JSON_PATH) {
    cachedJwks = loadJwksFromFile();
  } else {
    if (!PUBLIC_KEY_PATH) {
      throw new Error(
        'Set PUBLIC_KEY_PATH (and JWT_KID) or JWKS_JSON_PATH in .env — see .env.example'
      );
    }
    cachedJwks = await buildJwksFromPem();
  }

  if (PROVIDER_JWKS_JSON_PATH) {
    cachedProviderJwks = loadProviderJwksFromFile();
  } else if (PROVIDER_PUBLIC_KEY_PATH) {
    cachedProviderJwks = await buildProviderJwksFromPem();
  }

  if (PATIENT_JWKS_JSON_PATH) {
    cachedPatientJwks = loadPatientJwksFromFile();
  } else if (PATIENT_PUBLIC_KEY_PATH) {
    cachedPatientJwks = await buildPatientJwksFromPem();
  }
}

app.listen(PORT, async () => {
  try {
    await validateConfig();
  } catch (e) {
    console.error(e.message || e);
    process.exit(1);
  }
  console.log(`JWKS: http://localhost:${PORT}/.well-known/jwks.json`);
  console.log(`Health: http://localhost:${PORT}/health`);
  if (PROVIDER_PUBLIC_KEY_PATH || PROVIDER_JWKS_JSON_PATH) {
    console.log(`Provider JWKS: http://localhost:${PORT}/provider/.well-known/jwks.json`);
  }
  if (PATIENT_PUBLIC_KEY_PATH || PATIENT_JWKS_JSON_PATH) {
    console.log(`Patient JWKS: http://localhost:${PORT}/patient/.well-known/jwks.json`);
  }
  if (JWKS_JSON_PATH) {
    console.log(`Mode: JWKS_JSON_PATH=${JWKS_JSON_PATH}`);
  } else {
    const ecPart = EC_PUBLIC_KEY_PATH
      ? ` + EC ${process.env.EC_JWT_KID || ''} @ ${EC_PUBLIC_KEY_PATH}`
      : '';
    console.log(
      `Mode: PUBLIC_KEY_PATH=${PUBLIC_KEY_PATH} alg=${JWT_ALG} kid=${JWT_KID}${ecPart}`
    );
  }
});
