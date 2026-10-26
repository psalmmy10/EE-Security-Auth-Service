package com.pay.auth.service;

import com.pay.auth.dto.req.E2EDecryptToolRequest;
import com.pay.auth.dto.req.E2EEncryptToolRequest;
import com.pay.auth.dto.req.E2EProxyRequest;
import com.pay.auth.dto.res.E2EEncryptToolResponse;
import com.pay.auth.dto.res.E2EProxyResponse;
import com.fasterxml.jackson.databind.JsonNode;

/** DEV TOOL ONLY: does the client-side half of the E2E handshake so it can be tested from Postman. */
public interface E2ETestToolService {

    E2EEncryptToolResponse encrypt(E2EEncryptToolRequest request);

    JsonNode decrypt(E2EDecryptToolRequest request);

    /** Encrypts a plain request, sends it to the real endpoint over HTTP, decrypts the reply. */
    E2EProxyResponse proxy(E2EProxyRequest request);
}