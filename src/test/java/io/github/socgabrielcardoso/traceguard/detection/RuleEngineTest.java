package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleEngineTest {
    private static final Instant BASE = Instant.parse("2026-09-03T10:00:00Z");

    @Test
    void detectsBruteForceAndCompromisedAuthentication() {
        List<LogEvent> events = new ArrayList<>();
        for (int minute = 0; minute < 5; minute++) {
            events.add(event(minute + 1, minute, EventType.AUTH_FAILURE, "gabriel", "203.0.113.7", "Invalid password"));
        }
        events.add(event(6, 5, EventType.AUTH_SUCCESS, "gabriel", "203.0.113.7", "Accepted password"));

        List<Incident> incidents = RuleEngine.defaults().evaluate(events);

        assertTrue(hasRule(incidents, "AUTH-BRUTE-FORCE"));
        assertTrue(hasRule(incidents, "AUTH-SUCCESS-AFTER-FAILURES"));
    }

    @Test
    void detectsPasswordSprayAcrossAccounts() {
        List<LogEvent> events = List.of(
                event(1, 0, EventType.AUTH_FAILURE, "ana", "198.51.100.5", "Invalid password"),
                event(2, 1, EventType.AUTH_FAILURE, "bruno", "198.51.100.5", "Invalid password"),
                event(3, 2, EventType.AUTH_FAILURE, "carla", "198.51.100.5", "Invalid password"),
                event(4, 3, EventType.AUTH_FAILURE, "diego", "198.51.100.5", "Invalid password")
        );

        Incident incident = RuleEngine.defaults().evaluate(events).stream()
                .filter(item -> item.ruleId().equals("AUTH-PASSWORD-SPRAY"))
                .findFirst()
                .orElseThrow();

        assertEquals(Severity.CRITICAL, incident.severity());
        assertEquals(4, incident.evidence().size());
    }

    @Test
    void detectsDisabledSecurityControl() {
        LogEvent event = event(1, 0, EventType.SECURITY_CONTROL_DISABLED, "operator", "10.0.0.5", "Firewall disabled");

        Incident incident = RuleEngine.defaults().evaluate(List.of(event)).get(0);

        assertEquals("SYSTEM-SENSITIVE-CHANGE", incident.ruleId());
        assertEquals(98, incident.score());
    }

    private static boolean hasRule(List<Incident> incidents, String ruleId) {
        return incidents.stream().anyMatch(incident -> incident.ruleId().equals(ruleId));
    }

    private static LogEvent event(long line, long minute, EventType type, String user, String ip, String message) {
        return new LogEvent(
                "security.log",
                line,
                BASE.plus(minute, ChronoUnit.MINUTES),
                type,
                "srv-01",
                user,
                ip,
                message,
                Map.of()
        );
    }
}

