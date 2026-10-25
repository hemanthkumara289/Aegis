package com.aegis.common.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureTokenGeneratorTest {

    private final SecureTokenGenerator generator = new SecureTokenGenerator();

    @Test
    void nextBytesGeneratesExpectedLength() {
        byte[] bytes = generator.nextBytes(32);
        assertNotNull(bytes);
        assertEquals(32, bytes.length);
    }

    @Test
    void nextHexGeneratesExpectedLength() {
        String hex = generator.nextHex(16);
        assertNotNull(hex);
        assertEquals(32, hex.length());
        assertTrue(hex.matches("^[0-9a-f]{32}$"));
    }

    @Test
    void nextBase64UrlGeneratesNonEmptyString() {
        String token = generator.nextBase64Url(32);
        assertNotNull(token);
        assertTrue(token.length() > 0);
        assertTrue(token.matches("^[A-Za-z0-9_-]+$"));
    }

    @Test
    void nextAlphanumericGeneratesRequestedLength() {
        String token = generator.nextAlphanumeric(48);
        assertNotNull(token);
        assertEquals(48, token.length());
        assertTrue(token.matches("^[A-Za-z0-9]+$"));
    }

    @Test
    void nextNumericCodeGeneratesExactDigitCount() {
        String otp = generator.nextNumericCode(6);
        assertNotNull(otp);
        assertEquals(6, otp.length());
        assertTrue(otp.matches("^[0-9]{6}$"));
    }

    @Test
    void invalidLengthThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> generator.nextBytes(0));
        assertThrows(IllegalArgumentException.class, () -> generator.nextAlphanumeric(-1));
        assertThrows(IllegalArgumentException.class, () -> generator.nextNumericCode(0));
    }
}
