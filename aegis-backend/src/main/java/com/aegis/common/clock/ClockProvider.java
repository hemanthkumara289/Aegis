package com.aegis.common.clock;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

public interface ClockProvider {
    /**
     * Return the underlying Clock instance.
     */
    Clock getClock();

    /**
     * Return the current Instant as reported by the clock.
     */
    Instant now();

    /**
     * Return the ZoneId of the clock.
     */
    ZoneId getZone();
}
