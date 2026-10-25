package com.aegis.common.api;

import java.time.Instant;
import java.util.UUID;

public record ApiMeta(
    String requestId,
    Instant timestamp
) {
    public static ApiMeta now() {
        return new ApiMeta(UUID.randomUUID().toString(), Instant.now());
    }

    public static ApiMeta of(String requestId, Instant timestamp) {
        return new ApiMeta(requestId != null ? requestId : UUID.randomUUID().toString(), timestamp != null ? timestamp : Instant.now());
    }
}
