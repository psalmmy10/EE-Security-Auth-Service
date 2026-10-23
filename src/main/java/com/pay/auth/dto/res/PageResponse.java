package com.pay.auth.dto.res;

import org.springframework.data.domain.Page;

import java.util.List;

/** Stable paging contract; avoids serialising Spring's Page implementation details. */
public record PageResponse<T>(List<T> content, int page, int size, long totalElements, int totalPages, boolean last) {

    public static <T> PageResponse<T> from(Page<T> page) {
        return new PageResponse<>(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages(), page.isLast());
    }
}
