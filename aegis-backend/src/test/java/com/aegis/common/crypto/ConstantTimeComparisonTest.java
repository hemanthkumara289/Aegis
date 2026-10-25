package com.aegis.common.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConstantTimeComparisonTest {

    @Test
    void testByteArrayComparison() {
        byte[] a = "secret-token-12345".getBytes(StandardCharsets.UTF_8);
        byte[] b = "secret-token-12345".getBytes(StandardCharsets.UTF_8);
        byte[] c = "different-token-99".getBytes(StandardCharsets.UTF_8);

        assertTrue(ConstantTimeComparison.isEqual(a, b));
        assertFalse(ConstantTimeComparison.isEqual(a, c));
        assertFalse(ConstantTimeComparison.isEqual(a, null));
        assertFalse(ConstantTimeComparison.isEqual(null, b));
        assertTrue(ConstantTimeComparison.isEqual((byte[]) null, (byte[]) null));
    }

    @Test
    void testStringComparison() {
        String a = "hash_signature_abcdef123456";
        String b = "hash_signature_abcdef123456";
        String c = "hash_signature_abcdef123457";

        assertTrue(ConstantTimeComparison.isEqual(a, b));
        assertFalse(ConstantTimeComparison.isEqual(a, c));
        assertFalse(ConstantTimeComparison.isEqual(a, null));
        assertFalse(ConstantTimeComparison.isEqual(null, b));
        assertTrue(ConstantTimeComparison.isEqual((String) null, (String) null));
    }
}
