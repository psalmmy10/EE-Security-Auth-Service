package com.pay.auth.security.e2e;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

final class DecryptedHttpInputMessage implements HttpInputMessage {

    private final HttpHeaders headers;
    private final byte[] body;

    DecryptedHttpInputMessage(HttpHeaders original, byte[] body) {
        HttpHeaders copy = new HttpHeaders();
        copy.putAll(original);
        copy.setContentType(MediaType.APPLICATION_JSON);
        copy.setContentLength(body.length);
        this.headers = copy;
        this.body = body;
    }

    @Override
    public InputStream getBody() {
        return new ByteArrayInputStream(body);
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }
}
