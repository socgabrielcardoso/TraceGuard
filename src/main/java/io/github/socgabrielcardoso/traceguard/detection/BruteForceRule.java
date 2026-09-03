package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class BruteForceRule implements DetectionRule {
    private static final int THRESHOLD = 5;
    private static final Duration WINDOW = Duration.ofMinutes(5);

    @Override
    public String id() {
        return "AUTH-BRUTE-FORCE";
    }

    @Override
    public List<Incident> detect(List<LogEvent> events) {
        Map<String, List<LogEvent>> groups = events.stream()
                .filter(event -> event.type() == EventType.AUTH_FAILURE)
                .collect(Collectors.groupingBy(this::key));
        List<Incident> incidents = new ArrayList<>();

        for (Map.Entry<String, List<LogEvent>> entry : groups.entrySet()) {
            List<LogEvent> window = densestWindow(entry.getValue());
            if (window.size() >= THRESHOLD) {
                int score = Math.min(92, 72 + window.size() * 2);
                incidents.add(IncidentFactory.create(
                        id(),
                        "Repeated authentication failures",
                        Severity.HIGH,
                        score,
                        entry.getKey(),
                        window
                ));
            }
        }
        return incidents;
    }

    private List<LogEvent> densestWindow(List<LogEvent> events) {
        List<LogEvent> ordered = events.stream()
                .sorted((left, right) -> left.timestamp().compareTo(right.timestamp()))
                .toList();
        int bestStart = 0;
        int bestEnd = 0;
        int start = 0;

        for (int end = 0; end < ordered.size(); end++) {
            while (Duration.between(ordered.get(start).timestamp(), ordered.get(end).timestamp()).compareTo(WINDOW) > 0) {
                start++;
            }
            if (end - start > bestEnd - bestStart) {
                bestStart = start;
                bestEnd = end;
            }
        }
        return ordered.isEmpty() ? List.of() : ordered.subList(bestStart, bestEnd + 1);
    }

    private String key(LogEvent event) {
        return "user=" + event.identity() + ", source=" + event.origin();
    }
}

