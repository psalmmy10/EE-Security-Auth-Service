package com.pay.auth.service.impl;

import com.pay.auth.event.AuthAuditEvent;
import com.pay.auth.dao.entity.AuditLog;
import com.pay.auth.dao.repository.AuditLogRepository;
import com.pay.auth.service.AuditService;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {

    private static final int MAX_DETAIL_LENGTH = 500;

    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuthAuditEvent event) {
        auditLogRepository.save(AuditLog.of(
                event.type(),
                event.userId(),
                event.principal(),
                event.ipAddress(),
                event.userAgent(),
                truncate(event.detail()),
                event.occurredAt()));
    }

    private static String truncate(String value) {
        return value == null || value.length() <= MAX_DETAIL_LENGTH ? value : value.substring(0, MAX_DETAIL_LENGTH);
    }
}
