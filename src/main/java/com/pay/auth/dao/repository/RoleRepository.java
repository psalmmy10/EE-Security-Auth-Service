package com.pay.auth.dao.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.dao.entity.Role;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(RoleName name);
}
