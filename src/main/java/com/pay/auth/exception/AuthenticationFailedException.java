package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Raised for unknown email and wrong password alike, so responses never reveal which accounts exist. */
public class AuthenticationFailedException extends BaseException {

    public AuthenticationFailedException(String internalDetail) {
        super(ErrorCode.INVALID_CREDENTIALS, internalDetail);
    }

    public AuthenticationFailedException(String internalDetail, Throwable cause) {
        super(ErrorCode.INVALID_CREDENTIALS, internalDetail, cause);
    }
}
