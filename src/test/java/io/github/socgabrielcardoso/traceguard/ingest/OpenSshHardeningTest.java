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


    @Test
    void ignoresInvalidSyslogDates() {
        assertTrue(parser.parse("auth.log", 2, "Sep 35 12:00:00 edge sshd: Failed password for root from 198.51.100.2", clock).isEmpty());
    }


    @Test
    void acceptsIPv6AuthenticatedConnections() {
        LogEvent event = parser.parse("auth.log", 3, "Sep 3 09:00:00 edge sshd: Accepted publickey for alice from 2001:db8::1 port 22 ssh2", clock).orElseThrow();
        assertEquals("2001:db8::1", event.sourceIp());
    }


    @Test
    void identifiesInvalidUserPasswordFailures() {
        LogEvent event = parser.parse("auth.log", 4, "Sep 3 09:00:00 edge sshd: Failed password for invalid user scanner from 198.51.100.4 port 22", clock).orElseThrow();
        assertEquals(EventType.AUTH_FAILURE, event.type());
        assertEquals("scanner", event.user());
    }


    @Test
    void recognizesPAMAuthenticationFailures() {
        LogEvent event = parser.parse("auth.log", 5, "Sep 3 09:00:00 edge sshd: pam_unix(sshd:auth): authentication failure; rhost=198.51.100.6 user=dev", clock).orElseThrow();
        assertEquals("dev", event.user());
    }

}
