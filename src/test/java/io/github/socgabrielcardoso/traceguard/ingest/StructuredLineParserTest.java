package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StructuredLineParserTest {
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-03T12:00:00Z"), ZoneOffset.UTC);
    private final StructuredLineParser parser = new StructuredLineParser();

    @Test
    void parsesAliasesAndQuotedMessage() {
        String line = "2026-09-03T10:15:30Z action=login_failure hostname=dc-01 username=gabriel src_ip=203.0.113.9 message=\"Invalid password\"";

        LogEvent event = parser.parse("auth.log", 7, line, clock).orElseThrow();

        assertEquals(Instant.parse("2026-09-03T10:15:30Z"), event.timestamp());
        assertEquals(EventType.AUTH_FAILURE, event.type());
        assertEquals("dc-01", event.host());
        assertEquals("gabriel", event.user());
        assertEquals("203.0.113.9", event.sourceIp());
        assertEquals("Invalid password", event.message());
    }

    @Test
    void usesClockWhenTimestampIsMissing() {
        String line = "event=account_lockout user=operator host=dc-02";

        LogEvent event = parser.parse("audit.log", 1, line, clock).orElseThrow();

        assertEquals(clock.instant(), event.timestamp());
        assertEquals(EventType.ACCOUNT_LOCKOUT, event.type());
        assertTrue(event.message().contains("account_lockout"));
    }
}

