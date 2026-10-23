package com.pay.auth.mapper;

import org.springframework.stereotype.Component;

import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.entity.Role;
import com.pay.auth.entity.User;

/**
 * Entity -&gt; DTO boundary. Entities never leave the service layer, which guarantees the
 * password hash, lockout counters and version columns can't be serialised by accident.
 */
@Component
public class UserMapper {

    public UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getStatus(),
                user.getRoles().stream().map(Role::getName).map(Enum::name).sorted().toList(),
                user.getCreatedAt(),
                user.getLastLoginAt());
    }
}
