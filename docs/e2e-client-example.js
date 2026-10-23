/**
 * Reference browser/Node 20+ client for the Banffpay E2E envelope (WebCrypto only, no deps).
 *
 * Per request:
 *   1. random AES-256 key K, wrapped with the server RSA key (RSA-OAEP, SHA-256)
 *   2. body  -> AES-GCM(K, iv, JSON, AAD = "METHOD|PATH|TIMESTAMP|NONCE")
 *   3. reply -> AES-GCM(K, iv', JSON, AAD = "RESP|METHOD|PATH|NONCE")
 * PATH must be the URI path WITHOUT the query string (server uses getRequestURI()).
 */
const enc = (s) => new TextEncoder().encode(s);
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function createE2EClient(baseUrl) {
  const res = await fetch(`${baseUrl}/api/v1/crypto/public-key`);
  const { data } = await res.json();
  const serverKey = await crypto.subtle.importKey(
    'spki', unb64(data.publicKey), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  return { baseUrl, keyId: data.keyId, serverKey };
}

export async function secureFetch(client, method, pathWithQuery, body, accessToken) {
  const path = pathWithQuery.split('?')[0];
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, client.serverKey,
    await crypto.subtle.exportKey('raw', aesKey));
  const timestamp = Date.now().toString();
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));

  const headers = {
    'Content-Type': 'application/json',
    'X-E2E-Key': b64(wrappedKey),
    'X-E2E-Key-Id': client.keyId,
    'X-E2E-Timestamp': timestamp,
    'X-E2E-Nonce': nonce,
  };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  let payload;
  if (body !== undefined) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc(`${method}|${path}|${timestamp}|${nonce}`), tagLength: 128 },
      aesKey, enc(JSON.stringify(body)));
    payload = JSON.stringify({ iv: b64(iv), data: b64(ciphertext) });
  }

  const res = await fetch(client.baseUrl + pathWithQuery, { method, headers, body: payload });
  const json = await res.json();
  if (res.headers.get('X-E2E-Encrypted') !== 'true') {
    return { status: res.status, body: json }; // pre-key errors (e.g. 401, stale key id) are plaintext
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(json.iv), additionalData: enc(`RESP|${method}|${path}|${nonce}`), tagLength: 128 },
    aesKey, unb64(json.data));
  return { status: res.status, body: JSON.parse(new TextDecoder().decode(plaintext)) };
}

// Example:
// const c = await createE2EClient('http://localhost:8080');
// await secureFetch(c, 'POST', '/api/v1/auth/signup', { email, password, firstName, lastName });
// const { body } = await secureFetch(c, 'POST', '/api/v1/auth/login', { email, password });
// await secureFetch(c, 'GET', '/api/v1/users/me', undefined, body.data.accessToken);
