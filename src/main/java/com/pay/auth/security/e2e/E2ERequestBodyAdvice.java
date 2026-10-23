package com.pay.auth.security.e2e;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pay.auth.config.properties.E2EProperties;
import com.pay.auth.dto.common.EncryptedEnvelope;
import com.pay.auth.exception.E2EException;
import com.pay.auth.service.CryptoService;

import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * Decrypts {"iv","data"} into the plaintext JSON the controller expects, BEFORE Jackson
 * binding and @Valid run. A GCM tag failure (tampering, wrong key, wrong AAD) never binds.
 */
@ControllerAdvice
@RequiredArgsConstructor
public class E2ERequestBodyAdvice extends RequestBodyAdviceAdapter {

    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;
    private final E2EProperties properties;

    @Override
    public boolean supports(MethodParameter parameter, Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return properties.enabled()
                && AbstractJackson2HttpMessageConverter.class.isAssignableFrom(converterType)
                && E2EContextHolder.isEncryptionRequired(parameter.getContainingClass(), parameter.getMethod());
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        E2EContext context = E2EContextHolder.current()
                .orElseThrow(() -> E2EException.required("no E2E context: interceptor did not establish a key for this request"));
        EncryptedEnvelope envelope;
        try {
            envelope = objectMapper.readValue(inputMessage.getBody(), EncryptedEnvelope.class);
        } catch (JsonProcessingException ex) {
            throw E2EException.invalid("envelope not parseable");
        }
        if (envelope == null || !envelope.isComplete()) {
            throw E2EException.invalid("envelope incomplete");
        }
        byte[] plaintext = cryptoService.decrypt(context.key(), envelope, context.requestAad());
        return new DecryptedHttpInputMessage(inputMessage.getHeaders(), plaintext);
    }
}