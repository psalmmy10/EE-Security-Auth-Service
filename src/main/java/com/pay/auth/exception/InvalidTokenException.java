package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

public class InvalidTokenException extends BaseException {

    public InvalidTokenException(String internalDetail) {
        super(ErrorCode.INVALID_TOKEN, internalDetail);
    }
}
