package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Any cryptographic failure. Always mapped to one generic code: no padding/tag oracle. */
public class CryptoException extends BaseException {

    public CryptoException(String internalDetail) {
        super(ErrorCode.E2E_INVALID, internalDetail);
    }

    public CryptoException(String internalDetail, Throwable cause) {
        super(ErrorCode.E2E_INVALID, internalDetail, cause);
    }
}
