package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenSshHardeningTest {
    private final OpenSshLineParser parser = new OpenSshLineParser();
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-04T12:00:00Z"), ZoneOffset.UTC);

    @Test
    void ignoresNullLinesWithoutThrowing() {
        assertTrue(parser.parse("auth.log", 1, null, clock).isEmpty());
    }

}
