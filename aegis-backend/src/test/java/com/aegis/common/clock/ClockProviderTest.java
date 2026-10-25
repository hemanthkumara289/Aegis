package com.aegis.common.clock;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ClockProviderTest {

    @Test
    void systemClockProviderUsesSystemUtcByDefault() {
        SystemClockProvider clockProvider = new SystemClockProvider();
        assertNotNull(clockProvider.getClock());
        assertNotNull(clockProvider.now());
        assertEquals(ZoneOffset.UTC, clockProvider.getZone());
    }

    @Test
    void fixedClockProviderReturnsExactInstant() {
        Instant fixedInstant = Instant.parse("2026-10-24T12:00:00Z");
        Clock fixedClock = Clock.fixed(fixedInstant, ZoneOffset.UTC);

        SystemClockProvider clockProvider = new SystemClockProvider(fixedClock);

        assertEquals(fixedInstant, clockProvider.now());
        assertEquals(ZoneOffset.UTC, clockProvider.getZone());
        assertEquals(fixedClock, clockProvider.getClock());
    }
}
