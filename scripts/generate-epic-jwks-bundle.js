/**
 * Generates an Epic-doc-style JWKS with one RSA key + one EC P-384 key,
 * matching the public shape in Epic's JWT / JWKS examples.
 * Epic: EC keys are for JWKS served at a URL; static JWKS upload does not support EC.
 *
 * RSA: RS256 / RS384 / RS512 (pick when signing; default modulus 2048).
 * EC:  ES384 only (P-384 / secp384r1).
 *
 * Output:
 *   public/.well-known/jwks.json
 *   keys/rsa-private.pem, keys/rsa-public.pem
 *   keys/ec-private.pem, keys/ec-public.pem
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dotenv = require('dotenv');
const { exportJWK } = require('jose');

dotenv.config();

const root = path.join(__dirname, '..');

async function main() {
  const rsaKid =
    process.env.RSA_JWT_KID ||
    process.env.JWT_KID ||
    crypto.randomUUID();
  const ecKid = process.env.EC_JWT_KID || crypto.randomUUID();

  const rsaBits = Number(process.env.RSA_MODULUS_BITS || 2048);
  const rsa = crypto.generateKeyPairSync('rsa', {
    modulusLength: rsaBits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const ec = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp384r1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const rsaJwkRaw = await exportJWK(crypto.createPublicKey(rsa.publicKey));
  const ecJwkRaw = await exportJWK(crypto.createPublicKey(ec.publicKey));

  const jwks = {
    keys: [
      { kty: 'RSA', e: rsaJwkRaw.e, kid: rsaKid, n: rsaJwkRaw.n },
      { kty: 'EC', kid: ecKid, crv: ecJwkRaw.crv, x: ecJwkRaw.x, y: ecJwkRaw.y },
    ],
  };

  const keysDir = path.join(root, 'keys');
  fs.mkdirSync(keysDir, { recursive: true });
  fs.writeFileSync(path.join(keysDir, 'rsa-private.pem'), rsa.privateKey, 'utf8');
  fs.writeFileSync(path.join(keysDir, 'rsa-public.pem'), rsa.publicKey, 'utf8');
  fs.writeFileSync(path.join(keysDir, 'ec-private.pem'), ec.privateKey, 'utf8');
  fs.writeFileSync(path.join(keysDir, 'ec-public.pem'), ec.publicKey, 'utf8');

  const out = path.join(root, 'public', '.well-known', 'jwks.json');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(jwks, null, 2), 'utf8');

  console.log(`Wrote ${out}`);
  console.log('');
  console.log('RSA signing: keys/rsa-private.pem — algorithms RS256 / RS384 / RS512');
  console.log(`  kid (JWT header): ${rsaKid}`);
  console.log('EC signing:  keys/ec-private.pem — algorithm ES384 only (P-384)');
  console.log(`  kid (JWT header): ${ecKid}`);
  console.log('');
  console.log(
    'To serve this JWKS: set JWKS_JSON_PATH=./public/.well-known/jwks.json and comment out PUBLIC_KEY_PATH in .env'
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
