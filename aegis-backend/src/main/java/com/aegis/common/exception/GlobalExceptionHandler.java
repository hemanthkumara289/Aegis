package com.aegis.common.exception;

import com.aegis.common.api.ApiResponse;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AegisException.class)
    public ResponseEntity<ApiResponse<Void>> handleAegisException(AegisException ex) {
        log.warn("AegisException caught [{}]: {}", ex.getErrorCode().getCode(), ex.getMessage());
        ErrorDetail errorDetail = new ErrorDetail(
            ex.getErrorCode().getCode(),
            ex.getMessage(),
            ex.getDetails()
        );
        return ResponseEntity
            .status(ex.getHttpStatus())
            .body(ApiResponse.error(errorDetail));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(MethodArgumentNotValidException ex) {
        Map<String, Object> fieldErrors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fe.getField(), fe.getDefaultMessage());
        }

        ErrorDetail errorDetail = new ErrorDetail(
            ErrorCode.VALIDATION_FAILED.getCode(),
            "Validation failed for request",
            fieldErrors
        );
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ApiResponse.error(errorDetail));
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiResponse<Void>> handleConstraintViolationException(ConstraintViolationException ex) {
        Map<String, Object> violations = new HashMap<>();
        ex.getConstraintViolations().forEach(cv ->
            violations.put(cv.getPropertyPath().toString(), cv.getMessage())
        );

        ErrorDetail errorDetail = new ErrorDetail(
            ErrorCode.VALIDATION_FAILED.getCode(),
            "Constraint violation",
            violations
        );
        return ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .body(ApiResponse.error(errorDetail));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex) {
        log.error("Unhandled exception caught", ex);
        ErrorDetail errorDetail = new ErrorDetail(
            ErrorCode.INTERNAL_SERVER_ERROR.getCode(),
            "An unexpected error occurred. Please contact system administrator."
        );
        return ResponseEntity
            .status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(ApiResponse.error(errorDetail));
    }
}
