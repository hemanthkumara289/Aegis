package com.aegis.common.clock;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

@Component
public class SystemClockProvider implements ClockProvider {

    private final Clock clock;

    public SystemClockProvider() {
        this(Clock.systemUTC());
    }

    public SystemClockProvider(Clock clock) {
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @Override
    public Clock getClock() {
        return clock;
    }

    @Override
    public Instant now() {
        return clock.instant();
    }

    @Override
    public ZoneId getZone() {
        return clock.getZone();
    }
}
