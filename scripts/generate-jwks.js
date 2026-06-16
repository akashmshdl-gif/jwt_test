/**
 * Writes public/.well-known/jwks.json from PEM(s).
 * RSA: PUBLIC_KEY_PATH + JWT_KID
 * Optional EC (Epic-style two-key set): EC_PUBLIC_KEY_PATH + EC_JWT_KID
 */
const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { buildJwksFromPemEnv } = require('../lib/buildJwksFromPem.js');

dotenv.config();

const root = path.join(__dirname, '..');

const OUT =
  process.env.JWKS_OUT || path.join(root, 'public', '.well-known', 'jwks.json');

async function main() {
  const jwks = await buildJwksFromPemEnv(root);

  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(jwks, null, 2), 'utf8');
  console.log(`Wrote ${OUT} (${jwks.keys.length} key(s))`);
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
