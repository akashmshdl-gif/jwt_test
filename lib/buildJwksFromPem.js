/**
 * Builds a JWKS for Epic when keys are served from a JWKS URL (this app’s role).
 * Epic: EC keys are supported from a JWKS URL only—not from static JWKS upload in the app catalog.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { exportJWK } = require('jose');
const {
  shouldUseEpicStyle,
  formatEpicJwk,
  formatVerboseJwk,
} = require('./formatEpicJwk.js');

function resolvePath(baseDir, p) {
  if (!p) return '';
  if (path.isAbsolute(p)) return p;

  const candidates = [
    path.resolve(baseDir, p),
    path.resolve(process.cwd(), p),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }

  return candidates[0];
}

async function exportJwkFromPem(baseDir, relPath, label) {
  const pemPath = resolvePath(baseDir, relPath);
  if (!pemPath || !fs.existsSync(pemPath)) {
    throw new Error(`${label} not found or missing: ${relPath || '(empty)'}`);
  }
  const pem = fs.readFileSync(pemPath, 'utf8').trim();
  let keyObject;
  try {
    keyObject = crypto.createPublicKey(pem);
  } catch (e) {
    throw new Error(
      `Could not parse ${label} (${pemPath}): ${e.message}. Use X.509 (BEGIN CERTIFICATE) or SPKI (BEGIN PUBLIC KEY).`
    );
  }
  return exportJWK(keyObject);
}

function formatOne(raw, kid, alg) {
  if (!kid) throw new Error('kid is required');
  return shouldUseEpicStyle()
    ? formatEpicJwk(raw, kid)
    : formatVerboseJwk(raw, kid, alg);
}

/**
 * Build JWKS from env: RSA (PUBLIC_KEY_PATH + JWT_KID) and optional EC (EC_PUBLIC_KEY_PATH + EC_JWT_KID).
 * @param {string} baseDir - project root (directory that contains keys/)
 * @param {string} prefix - prefix for environment variables (e.g. 'PROVIDER_')
 */
async function buildJwksFromPemEnv(baseDir, prefix = '') {
  const PUBLIC_KEY_PATH = process.env[`${prefix}PUBLIC_KEY_PATH`] || '';
  const EC_PUBLIC_KEY_PATH = process.env[`${prefix}EC_PUBLIC_KEY_PATH`] || '';
  const JWT_KID = process.env[`${prefix}JWT_KID`] || process.env.JWT_KID || '';
  const EC_JWT_KID = process.env[`${prefix}EC_JWT_KID`] || process.env.EC_JWT_KID || '';
  const JWT_ALG = process.env[`${prefix}JWT_ALG`] || process.env.JWT_ALG || 'RS384';
  const JWT_ALG_EC = process.env[`${prefix}JWT_ALG_EC`] || process.env.JWT_ALG_EC || 'ES384';

  if (!PUBLIC_KEY_PATH) {
    throw new Error(`${prefix}PUBLIC_KEY_PATH is required (or use ${prefix}JWKS_JSON_PATH)`);
  }
  if (!JWT_KID) {
    throw new Error(`${prefix}JWT_KID is required when using ${prefix}PUBLIC_KEY_PATH`);
  }

  const rsaRaw = await exportJwkFromPem(baseDir, PUBLIC_KEY_PATH, `${prefix}PUBLIC_KEY_PATH`);
  if (rsaRaw.kty !== 'RSA') {
    throw new Error(`${prefix}PUBLIC_KEY_PATH must be an RSA public key or certificate`);
  }

  const keys = [formatOne(rsaRaw, JWT_KID, JWT_ALG)];

  if (EC_PUBLIC_KEY_PATH) {
    if (!EC_JWT_KID) {
      throw new Error(`${prefix}EC_JWT_KID is required when ${prefix}EC_PUBLIC_KEY_PATH is set`);
    }
    const ecRaw = await exportJwkFromPem(
      baseDir,
      EC_PUBLIC_KEY_PATH,
      `${prefix}EC_PUBLIC_KEY_PATH`
    );
    if (ecRaw.kty !== 'EC') {
      throw new Error(
        `${prefix}EC_PUBLIC_KEY_PATH must be an EC public key (SPKI PEM, e.g. secp384r1 / P-384)`
      );
    }
    if (ecRaw.crv !== 'P-384') {
      console.warn(
        '[jwks] EC curve is not P-384; Epic ES384 examples use curve P-384.'
      );
    }
    keys.push(formatOne(ecRaw, EC_JWT_KID, JWT_ALG_EC));
  }

  return { keys };
}

module.exports = {
  buildJwksFromPemEnv,
  resolvePath,
};
