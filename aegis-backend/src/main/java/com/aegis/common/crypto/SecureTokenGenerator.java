package com.aegis.common.crypto;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class SecureTokenGenerator {

    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String NUMERIC = "0123456789";

    private final SecureRandom secureRandom;

    public SecureTokenGenerator() {
        this.secureRandom = new SecureRandom();
    }

    public SecureTokenGenerator(SecureRandom secureRandom) {
        this.secureRandom = secureRandom != null ? secureRandom : new SecureRandom();
    }

    /**
     * Generates a byte array of the specified length using SecureRandom.
     */
    public byte[] nextBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive");
        }
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates a URL-safe Base64 string from random bytes without padding.
     */
    public String nextBase64Url(int byteCount) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nextBytes(byteCount));
    }

    /**
     * Generates a hexadecimal representation of random bytes.
     */
    public String nextHex(int byteCount) {
        return HexFormat.of().formatHex(nextBytes(byteCount));
    }

    /**
     * Generates a cryptographically random alphanumeric string of specified length.
     */
    public String nextAlphanumeric(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive");
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = secureRandom.nextInt(ALPHANUMERIC.length());
            sb.append(ALPHANUMERIC.charAt(index));
        }
        return sb.toString();
    }

    /**
     * Generates a cryptographically random numeric string (e.g. for 6-digit OTP).
     */
    public String nextNumericCode(int digits) {
        if (digits <= 0) {
            throw new IllegalArgumentException("Digits must be positive");
        }
        StringBuilder sb = new StringBuilder(digits);
        for (int i = 0; i < digits; i++) {
            int index = secureRandom.nextInt(NUMERIC.length());
            sb.append(NUMERIC.charAt(index));
        }
        return sb.toString();
    }
}
