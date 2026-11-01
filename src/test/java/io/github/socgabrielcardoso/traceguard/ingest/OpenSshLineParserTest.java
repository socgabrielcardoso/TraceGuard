package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenSshLineParserTest {
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-04T12:00:00Z"), ZoneOffset.UTC);
    private final OpenSshLineParser parser = new OpenSshLineParser();

    @Test
    void parsesFailedPassword() {
        String line = "Sep  3 10:15:12 edge-01 sshd[4042]: Failed password for invalid user admin from 198.51.100.24 port 44218 ssh2";

        LogEvent event = parser.parse("auth.log", 12, line, clock).orElseThrow();

        assertEquals(Instant.parse("2026-09-03T10:15:12Z"), event.timestamp());
        assertEquals(EventType.AUTH_FAILURE, event.type());
        assertEquals("admin", event.user());
        assertEquals("198.51.100.24", event.sourceIp());
        assertEquals("edge-01", event.host());
    }

    @Test
    void parsesSuccessfulPublicKey() {
        String line = "2026-09-03T10:20:12Z edge-01 sshd[4051]: Accepted publickey for gabriel from 198.51.100.24 port 44222 ssh2";

        LogEvent event = parser.parse("auth.log", 18, line, clock).orElseThrow();

        assertEquals(EventType.AUTH_SUCCESS, event.type());
        assertEquals("gabriel", event.user());
    }

    @Test
    void rejectsHostnamePrefixesInsteadOfReportingPartialIpAddresses() {
        String failure = "Sep  3 10:15:12 edge-01 sshd[4042]: Failed password for admin from bad.example port 22 ssh2";
        String success = "Sep  3 10:15:12 edge-01 sshd[4042]: Accepted publickey for admin from bad.example port 22 ssh2";

        assertTrue(parser.parse("auth.log", 20, failure, clock).isEmpty());
        assertTrue(parser.parse("auth.log", 21, success, clock).isEmpty());
    }

    @Test
    void stillAcceptsIpv6AuthenticationEvents() {
        String line = "Sep  3 10:15:12 edge-01 sshd[4042]: Failed password for admin from 2001:db8::42 port 22 ssh2";
        LogEvent event = parser.parse("auth.log", 22, line, clock).orElseThrow();

        assertEquals("2001:db8::42", event.sourceIp());
        assertEquals(EventType.AUTH_FAILURE, event.type());
    }

}

