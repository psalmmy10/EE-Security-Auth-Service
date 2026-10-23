package com.pay.auth.security.e2e;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pay.auth.constant.SecurityConstants;
import com.pay.auth.dto.common.EncryptedEnvelope;
import com.pay.auth.exception.CryptoException;
import com.pay.auth.service.CryptoService;

import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * Encrypts every JSON body (success AND error, since @ExceptionHandler results pass through
 * the same advice chain) whenever an E2E context was established for the request.
 */
@ControllerAdvice
@RequiredArgsConstructor
public class E2EResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return AbstractJackson2HttpMessageConverter.class.isAssignableFrom(converterType);
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        if (body == null || body instanceof EncryptedEnvelope || !(request instanceof ServletServerHttpRequest servletRequest)) {
            return body;
        }
        Object attribute = servletRequest.getServletRequest().getAttribute(E2EContext.REQUEST_ATTRIBUTE);
        if (!(attribute instanceof E2EContext context)) {
            return body;
        }
        try {
            byte[] plaintext = objectMapper.writeValueAsBytes(body);
            EncryptedEnvelope envelope = cryptoService.encrypt(context.key(), plaintext, context.responseAad());
            response.getHeaders().set(SecurityConstants.HEADER_E2E_ENCRYPTED, "true");
            return envelope;
        } catch (JsonProcessingException ex) {
            throw new CryptoException("unable to serialise response for encryption", ex);
        }
    }
}
