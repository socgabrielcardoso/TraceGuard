package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class SuccessAfterFailuresRule implements DetectionRule {
    private static final int FAILURE_THRESHOLD = 3;
    private static final Duration WINDOW = Duration.ofMinutes(10);

    @Override
    public String id() {
        return "AUTH-SUCCESS-AFTER-FAILURES";
    }

    @Override
    public List<Incident> detect(List<LogEvent> events) {
        List<LogEvent> ordered = events.stream()
                .filter(event -> event.type() == EventType.AUTH_FAILURE || event.type() == EventType.AUTH_SUCCESS)
                .sorted((left, right) -> left.timestamp().compareTo(right.timestamp()))
                .toList();
        List<Incident> incidents = new ArrayList<>();

        for (LogEvent success : ordered) {
            if (success.type() != EventType.AUTH_SUCCESS) {
                continue;
            }
            List<LogEvent> evidence = ordered.stream()
                    .filter(event -> event.type() == EventType.AUTH_FAILURE)
                    .filter(event -> sameActor(event, success))
                    .filter(event -> !event.timestamp().isAfter(success.timestamp()))
                    .filter(event -> Duration.between(event.timestamp(), success.timestamp()).compareTo(WINDOW) <= 0)
                    .toList();
            if (evidence.size() >= FAILURE_THRESHOLD) {
                List<LogEvent> completeEvidence = new ArrayList<>(evidence);
                completeEvidence.add(success);
                incidents.add(IncidentFactory.create(
                        id(),
                        "Successful authentication after repeated failures",
                        Severity.HIGH,
                        Math.min(96, 80 + evidence.size() * 2),
                        "user=" + success.identity() + ", source=" + success.origin(),
                        completeEvidence
                ));
            }
        }
        return incidents;
    }

    private boolean sameActor(LogEvent left, LogEvent right) {
        return left.identity().equals(right.identity()) && left.origin().equals(right.origin());
    }
}

