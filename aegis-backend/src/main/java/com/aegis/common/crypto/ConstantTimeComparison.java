package com.aegis.common.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Constant-time comparison utility to prevent side-channel timing attacks
 * when comparing sensitive strings or byte arrays (e.g., HMAC signatures,
 * tokens, password hashes, or OTP codes).
 */
public final class ConstantTimeComparison {

    private ConstantTimeComparison() {
        // utility class
    }

    /**
     * Compares two byte arrays in constant time.
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if both arrays are equal, false otherwise
     */
    public static boolean isEqual(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Compares two UTF-8 strings in constant time.
     *
     * @param a first string
     * @param b second string
     * @return true if both strings are equal, false otherwise
     */
    public static boolean isEqual(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        return MessageDigest.isEqual(
            a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8)
        );
    }
}
