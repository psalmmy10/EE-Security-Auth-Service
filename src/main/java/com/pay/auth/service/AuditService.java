package com.pay.auth.service;

import com.pay.auth.event.AuthAuditEvent;

public interface AuditService {

    void record(AuthAuditEvent event);
}
