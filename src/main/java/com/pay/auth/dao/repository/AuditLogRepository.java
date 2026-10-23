package com.pay.auth.dao.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pay.auth.dao.entity.AuditLog;

import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
}
