package com.aegis.common.api;

import com.aegis.common.exception.ErrorDetail;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiResponseSerializationTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Test
    void successResponseSerializesExplicitNullError() throws Exception {
        ApiMeta meta = new ApiMeta("req-12345", Instant.parse("2026-10-25T12:00:00Z"));
        ApiResponse<Map<String, String>> response = ApiResponse.success(Map.of("key", "value"), meta);

        String json = objectMapper.writeValueAsString(response);
        JsonNode rootNode = objectMapper.readTree(json);

        assertTrue(rootNode.get("success").asBoolean());
        assertEquals("value", rootNode.get("data").get("key").asText());
        assertTrue(rootNode.has("error"), "Envelope must contain 'error' field");
        assertTrue(rootNode.get("error").isNull(), "'error' field must be explicit null on success");
        assertEquals("req-12345", rootNode.get("meta").get("requestId").asText());
        assertEquals("2026-10-25T12:00:00Z", rootNode.get("meta").get("timestamp").asText());
    }

    @Test
    void errorResponseSerializesExplicitNullDataAndOmitsNullDetails() throws Exception {
        ApiMeta meta = new ApiMeta("req-67890", Instant.parse("2026-10-25T12:05:00Z"));
        ApiResponse<Void> response = ApiResponse.error(
            new ErrorDetail("APPROVAL_ALREADY_EXECUTED", "Approval request was already executed"),
            meta
        );

        String json = objectMapper.writeValueAsString(response);
        JsonNode rootNode = objectMapper.readTree(json);

        assertFalse(rootNode.get("success").asBoolean());
        assertTrue(rootNode.has("data"), "Envelope must contain 'data' field");
        assertTrue(rootNode.get("data").isNull(), "'data' field must be explicit null on error");

        JsonNode errorNode = rootNode.get("error");
        assertNotNull(errorNode);
        assertEquals("APPROVAL_ALREADY_EXECUTED", errorNode.get("code").asText());
        assertEquals("Approval request was already executed", errorNode.get("message").asText());
        assertFalse(errorNode.has("details"), "Optional 'details' should be omitted when null in ErrorDetail");

        assertEquals("req-67890", rootNode.get("meta").get("requestId").asText());
    }

    @Test
    void errorResponseIncludesDetailsWhenPresent() throws Exception {
        ApiMeta meta = new ApiMeta("req-99999", Instant.parse("2026-10-25T12:10:00Z"));
        ApiResponse<Void> response = ApiResponse.error(
            new ErrorDetail("VALIDATION_FAILED", "Validation failed for request", Map.of("email", "must not be blank")),
            meta
        );

        String json = objectMapper.writeValueAsString(response);
        JsonNode rootNode = objectMapper.readTree(json);

        assertFalse(rootNode.get("success").asBoolean());
        assertTrue(rootNode.get("data").isNull());

        JsonNode errorNode = rootNode.get("error");
        assertTrue(errorNode.has("details"));
        assertEquals("must not be blank", errorNode.get("details").get("email").asText());
    }
}
