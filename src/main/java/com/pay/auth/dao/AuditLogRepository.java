package com.pay.auth.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pay.auth.entity.AuditLog;

import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
}
