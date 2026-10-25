package com.aegis.common.exception;

import org.springframework.http.HttpStatus;

public enum ErrorCode {
    // 400 Validation / Bad Request
    VALIDATION_FAILED("VALIDATION_FAILED", HttpStatus.BAD_REQUEST, "Validation failed for request"),
    BAD_REQUEST("BAD_REQUEST", HttpStatus.BAD_REQUEST, "Malformed request syntax or parameters"),

    // 401 Authentication
    INVALID_CREDENTIALS("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED, "Invalid email or password"),
    UNAUTHORIZED("UNAUTHORIZED", HttpStatus.UNAUTHORIZED, "Authentication credentials missing or invalid"),
    TOKEN_EXPIRED("TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED, "Access token has expired"),
    TOKEN_INVALID("TOKEN_INVALID", HttpStatus.UNAUTHORIZED, "Token signature or structure is invalid"),
    REFRESH_TOKEN_REUSED("REFRESH_TOKEN_REUSED", HttpStatus.UNAUTHORIZED, "Refresh token replay detected"),
    OTP_INVALID("OTP_INVALID", HttpStatus.UNAUTHORIZED, "Invalid OTP code"),
    CHALLENGE_MISMATCH("CHALLENGE_MISMATCH", HttpStatus.UNAUTHORIZED, "Challenge binding verification failed"),

    // 403 Forbidden
    FORBIDDEN("FORBIDDEN", HttpStatus.FORBIDDEN, "Access to requested resource is forbidden"),
    INSUFFICIENT_PERMISSIONS("INSUFFICIENT_PERMISSIONS", HttpStatus.FORBIDDEN, "User lacks required permission"),
    SOD_VIOLATION("SOD_VIOLATION", HttpStatus.FORBIDDEN, "Separation of duties policy violation"),

    // 404 Not Found
    RESOURCE_NOT_FOUND("RESOURCE_NOT_FOUND", HttpStatus.NOT_FOUND, "Requested resource does not exist"),

    // 409 Conflict / State violations / Replay
    CONFLICT("CONFLICT", HttpStatus.CONFLICT, "Resource state conflict"),
    EMAIL_ALREADY_REGISTERED("EMAIL_ALREADY_REGISTERED", HttpStatus.CONFLICT, "User email is already registered"),
    INVALID_STATE_TRANSITION("INVALID_STATE_TRANSITION", HttpStatus.CONFLICT, "Illegal state transition requested"),
    APPROVAL_ALREADY_EXECUTED("APPROVAL_ALREADY_EXECUTED", HttpStatus.CONFLICT, "Approval request was already executed"),
    APPROVAL_NOT_APPROVED("APPROVAL_NOT_APPROVED", HttpStatus.CONFLICT, "Approval request is not in APPROVED state"),
    PAYLOAD_HASH_MISMATCH("PAYLOAD_HASH_MISMATCH", HttpStatus.CONFLICT, "Payload integrity verification failed"),

    // 410 Gone
    OTP_EXPIRED("OTP_EXPIRED", HttpStatus.GONE, "OTP has expired"),

    // 429 Too Many Requests
    RATE_LIMIT_EXCEEDED("RATE_LIMIT_EXCEEDED", HttpStatus.TOO_MANY_REQUESTS, "Request rate limit exceeded"),
    OTP_ATTEMPTS_EXHAUSTED("OTP_ATTEMPTS_EXHAUSTED", HttpStatus.TOO_MANY_REQUESTS, "Maximum OTP verification attempts exceeded"),

    // 500 Internal Server Error
    INTERNAL_SERVER_ERROR("INTERNAL_SERVER_ERROR", HttpStatus.INTERNAL_SERVER_ERROR, "An internal server error occurred");

    private final String code;
    private final HttpStatus httpStatus;
    private final String defaultMessage;

    ErrorCode(String code, HttpStatus httpStatus, String defaultMessage) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public String getCode() {
        return code;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
