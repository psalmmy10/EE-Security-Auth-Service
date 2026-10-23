package com.pay.auth.exception;

import com.pay.auth.constant.enums.ErrorCode;

/** Back-pressure signal when a bounded resource (e.g. password hashing) is saturated. */
public class ServiceBusyException extends BaseException {

    public ServiceBusyException(String internalDetail) {
        super(ErrorCode.SERVICE_BUSY, internalDetail);
    }

    public ServiceBusyException(String internalDetail, Throwable cause) {
        super(ErrorCode.SERVICE_BUSY, internalDetail, cause);
    }
}
