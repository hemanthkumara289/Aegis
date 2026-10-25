package com.aegis.common.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorDetail(
    String code,
    String message,
    Map<String, Object> details
) {
    public ErrorDetail(String code, String message) {
        this(code, message, null);
    }
}
