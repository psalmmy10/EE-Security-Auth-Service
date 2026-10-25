
(() => {
    "use strict";

    const PUBLIC_KEY_URL = "/api/v1/crypto/public-key";
    const API_DOCS_URL = "/v3/api-docs";

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    // Keep each request's AES key separate, even for concurrent requests.
    const pendingRequests = new Map();

    let publicKeyPromise = null;

    /*
     * Only encrypt endpoints protected by @E2EEncrypted.
     * Adjust these rules if your actual controller mappings differ.
     */
    function isE2EPath(path) {
        return (
            /^\/api\/v1\/auth\/(signup|login|refresh|logout|logout-all)\/?$/.test(path)
            || /^\/api\/v1\/admin(?:\/|$)/.test(path)
        );
    }

    function toBase64(bytes) {
        let binary = "";

        for (const byte of bytes) {
            binary += String.fromCharCode(byte);
        }

        return btoa(binary);
    }

    function fromBase64(value) {
        const binary = atob(value);

        return Uint8Array.from(
            binary,
            character => character.charCodeAt(0)
        );
    }

    function getHeader(headers, name) {
        if (!headers) {
            return undefined;
        }

        const matchingKey = Object.keys(headers).find(
            key => key.toLowerCase() === name.toLowerCase()
        );

        return matchingKey ? headers[matchingKey] : undefined;
    }

    /*
     * Fetch the existing public key.
     *
     * Your API returns:
     * {
     *   "success": true,
     *   "data": {
     *     "keyId": "...",
     *     "keyAlgorithm": "RSA-OAEP-256",
     *     "contentEncryption": "A256GCM",
     *     "publicKey": "BASE64..."
     *   }
     * }
     */
    async function getServerPublicKey() {
        if (!publicKeyPromise) {
            publicKeyPromise = (async () => {
                const response = await fetch(PUBLIC_KEY_URL, {
                    method: "GET",
                    headers: {
                        "Accept": "application/json"
                    }
                });

                if (!response.ok) {
                    throw new Error(
                        "Public-key request failed with HTTP "
                        + response.status
                    );
                }

                const apiResponse = await response.json();
                const keyData = apiResponse.data;

                if (
                    !apiResponse.success
                    || !keyData
                    || !keyData.keyId
                    || !keyData.publicKey
                ) {
                    throw new Error(
                        "Public key response is missing data.keyId "
                        + "or data.publicKey"
                    );
                }

                const rsaPublicKey = await crypto.subtle.importKey(
                    "spki",
                    fromBase64(keyData.publicKey),
                    {
                        name: "RSA-OAEP",
                        hash: "SHA-256"
                    },
                    false,
                    ["encrypt"]
                );

                return {
                    keyId: keyData.keyId,
                    rsaPublicKey
                };
            })().catch(error => {
                publicKeyPromise = null;
                throw error;
            });
        }

        return publicKeyPromise;
    }

    /*
     * Generate a new AES-256 key for each request,
     * then wrap it with the server's RSA public key.
     */
    async function createSession() {
        const serverKey = await getServerPublicKey();

        const aesKey = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        const rawAesKey = await crypto.subtle.exportKey(
            "raw",
            aesKey
        );

        const wrappedKey = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            serverKey.rsaPublicKey,
            rawAesKey
        );

        return {
            keyId: serverKey.keyId,
            aesKey,
            wrappedKey: toBase64(new Uint8Array(wrappedKey))
        };
    }

    function randomNonce() {
        return toBase64(crypto.getRandomValues(new Uint8Array(16)));
    }

    /*
     * Request AAD must exactly match:
     * METHOD|REQUEST_URI|TIMESTAMP|NONCE
     */
    async function encryptRequestBody(
        aesKey,
        plaintext,
        method,
        path,
        timestamp,
        nonce
    ) {
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const aad = `${method}|${path}|${timestamp}|${nonce}`;

        const ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode(aad),
                tagLength: 128
            },
            aesKey,
            encoder.encode(plaintext)
        );

        return {
            iv: toBase64(iv),
            data: toBase64(new Uint8Array(ciphertext))
        };
    }

    /*
     * Called by Swagger before the HTTP request is sent.
     */
    async function requestInterceptor(request) {
        const url = new URL(request.url, window.location.origin);
        const path = url.pathname;
        const method = (request.method || "GET").toUpperCase();

        if (!isE2EPath(path)) {
            return request;
        }

        const session = await createSession();
        const timestamp = String(Date.now());
        const nonce = randomNonce();

        request.headers = request.headers || {};

        request.headers["X-E2E-Key"] = session.wrappedKey;
        request.headers["X-E2E-Key-Id"] = session.keyId;
        request.headers["X-E2E-Timestamp"] = timestamp;
        request.headers["X-E2E-Nonce"] = nonce;

        // Remember the key and the exact AAD inputs for this response.
        pendingRequests.set(nonce, {
            aesKey: session.aesKey,
            method,
            path
        });

        // Encrypt a body only when Swagger supplied one.
        if (
            request.body !== undefined
            && request.body !== null
            && request.body !== ""
        ) {
            const plaintext = typeof request.body === "string"
                ? request.body
                : JSON.stringify(request.body);

            const encryptedEnvelope = await encryptRequestBody(
                session.aesKey,
                plaintext,
                method,
                path,
                timestamp,
                nonce
            );

            request.body = JSON.stringify(encryptedEnvelope);
            request.headers["Content-Type"] = "application/json";
        }

        return request;
    }

    /*
     * Response AAD must exactly match:
     * RESP|METHOD|REQUEST_URI|NONCE
     */
    async function responseInterceptor(response) {
        const encryptedHeader = getHeader(
            response.headers,
            "X-E2E-Encrypted"
        );

        const nonce = getHeader(
            response.headers,
            "X-E2E-Request-Nonce"
        );

        if (!nonce) {
            return response;
        }

        const session = pendingRequests.get(nonce);

        if (!session) {
            return response;
        }

        // This request's response has arrived, so release its key reference.
        pendingRequests.delete(nonce);

        if (String(encryptedHeader).toLowerCase() !== "true") {
            return response;
        }

        const rawBody = typeof response.text === "string"
            ? response.text
            : typeof response.body === "string"
                ? response.body
                : null;

        if (!rawBody) {
            throw new Error(
                "Encrypted response body was not available as text"
            );
        }

        const envelope = JSON.parse(rawBody);

        if (!envelope.iv || !envelope.data) {
            throw new Error(
                "Encrypted response is missing iv or data"
            );
        }

        const aad =
            `RESP|${session.method}|${session.path}|${nonce}`;

        const plaintextBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: fromBase64(envelope.iv),
                additionalData: encoder.encode(aad),
                tagLength: 128
            },
            session.aesKey,
            fromBase64(envelope.data)
        );

        const plaintext = decoder.decode(plaintextBuffer);

        response.text = plaintext;
        response.data = JSON.parse(plaintext);
        response.body = response.data;
        response.obj = response.data;

        return response;
    }

    window.addEventListener("load", () => {
        SwaggerUIBundle({
            url: API_DOCS_URL,
            dom_id: "#swagger-ui",
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            layout: "StandaloneLayout",
            requestInterceptor,
            responseInterceptor
        });
    });
})();
