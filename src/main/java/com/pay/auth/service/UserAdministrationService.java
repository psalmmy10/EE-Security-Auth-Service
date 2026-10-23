package com.pay.auth.service;

import java.util.UUID;

import com.pay.auth.constant.enums.RoleName;
import com.pay.auth.dto.req.UpdateUserStatusRequest;
import com.pay.auth.dto.res.PageResponse;
import com.pay.auth.dto.res.UserResponse;
import com.pay.auth.model.ClientContext;

public interface UserAdministrationService {

    PageResponse<UserResponse> listUsers(int page, int size);

    UserResponse getUser(UUID userId);

    UserResponse updateStatus(UUID actorId, UUID userId, UpdateUserStatusRequest request, ClientContext client);

    UserResponse assignRole(UUID actorId, UUID userId, RoleName role, ClientContext client);

    UserResponse revokeRole(UUID actorId, UUID userId, RoleName role, ClientContext client);

    /** @return true if created, false if an account with that email already existed */
    boolean ensureBootstrapAdmin(String email, String rawPassword, String firstName, String lastName);
}
