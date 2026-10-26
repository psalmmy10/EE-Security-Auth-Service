package com.pay.auth.controller;

import com.pay.auth.constant.ApiPaths;
import com.pay.auth.dto.req.E2EDecryptToolRequest;
import com.pay.auth.dto.req.E2EEncryptToolRequest;
import com.pay.auth.dto.req.E2EProxyRequest;
import com.pay.auth.dto.res.ApiResponse;
import com.pay.auth.dto.res.E2EEncryptToolResponse;
import com.pay.auth.dto.res.E2EProxyResponse;
import com.pay.auth.exception.OperationNotAllowedException;
import com.pay.auth.service.E2ETestToolService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * DEV TOOL ONLY — lets Postman (or curl) test encrypted endpoints without client-side crypto.
 * <ul>
 *   <li>Exists only under the "dev" profile; staging/prod never load it (404).</li>
 *   <li>Answers only callers on this machine or a private network (incl. Docker).</li>
 *   <li>Deliberately NOT @E2EEncrypted: it is the client side of the handshake.</li>
 * </ul>
 */
@Slf4j
@Profile("dev")
@RestController
@RequestMapping(ApiPaths.DEV_E2E)
public class DevE2EToolController {

    private final E2ETestToolService toolService;

    public DevE2EToolController(E2ETestToolService toolService) {
        this.toolService = toolService;
        log.warn("DEV E2E test endpoints enabled at {}/proxy, /encrypt, /decrypt (dev profile only)", ApiPaths.DEV_E2E);
    }

    /** Plain request in; encrypted round trip through the real endpoint; plain reply out. */
    @PostMapping("/proxy")
    public ResponseEntity<ApiResponse<E2EProxyResponse>> proxy(@Valid @RequestBody E2EProxyRequest request,
                                                               HttpServletRequest http) {
        requireLocalCaller(http);
        return ResponseEntity.ok(ApiResponse.success(toolService.proxy(request), "Sent encrypted; reply decrypted"));
    }

    @PostMapping("/encrypt")
    public ResponseEntity<ApiResponse<E2EEncryptToolResponse>> encrypt(@Valid @RequestBody E2EEncryptToolRequest request,
                                                                       HttpServletRequest http) {
        requireLocalCaller(http);
        return ResponseEntity.ok(ApiResponse.success(toolService.encrypt(request),
                "Add the headers and body to the real request and send it before validUntil"));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<ApiResponse<JsonNode>> decrypt(@Valid @RequestBody E2EDecryptToolRequest request,
                                                         HttpServletRequest http) {
        requireLocalCaller(http);
        return ResponseEntity.ok(ApiResponse.success(toolService.decrypt(request), "Decrypted response"));
    }

    private static void requireLocalCaller(HttpServletRequest http) {
        try {
            InetAddress caller = InetAddress.getByName(http.getRemoteAddr());   // literal IP, no DNS lookup
            if (caller.isLoopbackAddress() || caller.isSiteLocalAddress()) {
                return;
            }
        } catch (UnknownHostException ignored) {
            // fall through to rejection
        }
        throw new OperationNotAllowedException("dev E2E tool called from non-local address " + http.getRemoteAddr());
    }
}
