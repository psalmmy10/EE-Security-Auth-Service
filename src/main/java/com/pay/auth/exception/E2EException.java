package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

public class E2EException extends BaseException {

    private E2EException(ErrorCode errorCode, String internalDetail) {
        super(errorCode, internalDetail);
    }

    public static E2EException required() {
        return new E2EException(ErrorCode.E2E_REQUIRED, "missing E2E headers or context");
    }

 
    public static E2EException required(String internalDetail) {
        return new E2EException(ErrorCode.E2E_REQUIRED, internalDetail);
    }
 
    public static E2EException invalid(String internalDetail) {
        return new E2EException(ErrorCode.E2E_INVALID, internalDetail);
    }
 
    public static E2EException keyMismatch() {
        return new E2EException(ErrorCode.E2E_KEY_MISMATCH, "client used a stale or unknown key id");
    }
}
