package com.pay.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.dto.res.ApiResponse;
import com.pay.auth.dto.res.PublicKeyResponse;
import com.pay.auth.service.CryptoService;

import java.time.Duration;

/** Public, unencrypted by design: clients need this key before they can encrypt anything. */
@RestController
@RequestMapping(ApiPaths.CRYPTO)
@RequiredArgsConstructor
public class CryptoController {

    private final CryptoService cryptoService;

    @GetMapping("/public-key")
    public ResponseEntity<ApiResponse<PublicKeyResponse>> publicKey() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(10)).cachePublic())
                .body(ApiResponse.success(cryptoService.publicKey(), "Payload encryption key"));
    }
}
