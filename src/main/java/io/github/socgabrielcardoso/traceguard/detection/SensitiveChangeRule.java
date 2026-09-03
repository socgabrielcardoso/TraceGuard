package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.util.ArrayList;
import java.util.List;

public final class SensitiveChangeRule implements DetectionRule {
    @Override
    public String id() {
        return "SYSTEM-SENSITIVE-CHANGE";
    }

    @Override
    public List<Incident> detect(List<LogEvent> events) {
        List<Incident> incidents = new ArrayList<>();
        for (LogEvent event : events) {
            Incident incident = switch (event.type()) {
                case SECURITY_CONTROL_DISABLED -> create(
                        event,
                        "Security control disabled",
                        Severity.CRITICAL,
                        98
                );
                case PRIVILEGE_CHANGE -> create(
                        event,
                        "Privileged access changed",
                        Severity.HIGH,
                        86
                );
                case ACCOUNT_LOCKOUT -> create(
                        event,
                        "Account lockout detected",
                        Severity.MEDIUM,
                        62
                );
                default -> null;
            };
            if (incident != null) {
                incidents.add(incident);
            }
        }
        return incidents;
    }

    private Incident create(LogEvent event, String title, Severity severity, int score) {
        String entity = !event.host().isBlank()
                ? "host=" + event.host() + ", user=" + event.identity()
                : "user=" + event.identity();
        return IncidentFactory.create(id(), title, severity, score, entity, List.of(event));
    }
}

