/**
 * Epic documentation JWKS shape: RSA uses kty, e, kid, n; EC uses kty, kid, crv, x, y
 * (no use/alg in their example — algorithms come from your signing setup).
 */

function shouldUseEpicStyle() {
  const v = process.env.JWK_EPIC_STYLE;
  if (v === undefined || v === '') return true;
  return v === '1' || /^true$/i.test(v);
}

/** @param {Record<string, unknown>} jwk from exportJWK(createPublicKey(...)) */
function formatEpicJwk(jwk, kid) {
  if (!kid) throw new Error('kid is required for Epic-style JWK');
  if (jwk.kty === 'RSA') {
    return { kty: 'RSA', e: jwk.e, kid, n: jwk.n };
  }
  if (jwk.kty === 'EC') {
    return { kty: 'EC', kid, crv: jwk.crv, x: jwk.x, y: jwk.y };
  }
  throw new Error(`Unsupported kty for Epic-style JWK: ${jwk.kty}`);
}

/** Verbose JWKS fields (optional interoperability). */
function formatVerboseJwk(raw, kid, alg) {
  const jwk = { ...raw, kid, use: 'sig', alg };
  return jwk;
}

module.exports = {
  shouldUseEpicStyle,
  formatEpicJwk,
  formatVerboseJwk,
};
