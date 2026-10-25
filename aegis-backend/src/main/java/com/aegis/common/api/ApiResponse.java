package com.aegis.common.api;

import com.aegis.common.exception.ErrorDetail;
public record ApiResponse<T>(
    boolean success,
    T data,
    ErrorDetail error,
    ApiMeta meta
) {
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data, null, ApiMeta.now());
    }

    public static <T> ApiResponse<T> success(T data, ApiMeta meta) {
        return new ApiResponse<>(true, data, null, meta);
    }

    public static <T> ApiResponse<T> error(ErrorDetail error) {
        return new ApiResponse<>(false, null, error, ApiMeta.now());
    }

    public static <T> ApiResponse<T> error(ErrorDetail error, ApiMeta meta) {
        return new ApiResponse<>(false, null, error, meta);
    }

    public static <T> ApiResponse<T> error(String code, String message) {
        return new ApiResponse<>(false, null, new ErrorDetail(code, message), ApiMeta.now());
    }
}
