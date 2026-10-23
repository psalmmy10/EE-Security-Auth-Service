package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

import lombok.Getter;

/**
 * Root of all domain exceptions. The exception message is an INTERNAL diagnostic for logs;
 * clients only ever see {@link ErrorCode#getMessage()}.
 */
@Getter
public abstract class BaseException extends RuntimeException {

    private final transient ErrorCode errorCode;

    protected BaseException(ErrorCode errorCode, String internalDetail) {
        super(internalDetail);
        this.errorCode = errorCode;
    }

    protected BaseException(ErrorCode errorCode, String internalDetail, Throwable cause) {
        super(internalDetail, cause);
        this.errorCode = errorCode;
    }
}
