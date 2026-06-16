/**
 * Creates keys/public.pem + keys/private.pem for local dev if missing.
 * Sandbox only — use your real Epic key pair for production.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dotenv = require('dotenv');

dotenv.config();

const root = path.join(__dirname, '..');
const DEFAULT_PUBLIC = './keys/public.pem';

function resolveFromRoot(p) {
  return path.isAbsolute(p) ? p : path.join(root, p);
}

const publicRel = process.env.PUBLIC_KEY_PATH || DEFAULT_PUBLIC;
const publicPath = resolveFromRoot(publicRel);
const isDefaultLocation =
  !process.env.PUBLIC_KEY_PATH ||
  path.normalize(publicRel) === path.normalize(DEFAULT_PUBLIC);

if (fs.existsSync(publicPath)) {
  process.exit(0);
}

if (!isDefaultLocation) {
  console.error(
    `Missing public key: ${publicPath}\n` +
      `Add your RSA public PEM there, or set PUBLIC_KEY_PATH to ./keys/public.pem and run: npm run setup:dev`
  );
  process.exit(1);
}

const keysDir = path.join(root, 'keys');
fs.mkdirSync(keysDir, { recursive: true });

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const pubPath = path.join(keysDir, 'public.pem');
const privPath = path.join(keysDir, 'private.pem');
fs.writeFileSync(pubPath, publicKey, 'utf8');
fs.writeFileSync(privPath, privateKey, 'utf8');

console.warn(
  '[ensure-dev-keys] Created sandbox-only RSA keys in keys/. Do not use for production or Epic production registration.'
);
