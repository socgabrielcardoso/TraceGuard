package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class PasswordSprayRule implements DetectionRule {
    private static final int DISTINCT_USERS = 4;
    private static final Duration WINDOW = Duration.ofMinutes(10);

    @Override
    public String id() {
        return "AUTH-PASSWORD-SPRAY";
    }

    @Override
    public List<Incident> detect(List<LogEvent> events) {
        Map<String, List<LogEvent>> groups = events.stream()
                .filter(event -> event.type() == EventType.AUTH_FAILURE)
                .filter(event -> !event.sourceIp().isBlank())
                .collect(Collectors.groupingBy(LogEvent::origin));
        List<Incident> incidents = new ArrayList<>();

        for (Map.Entry<String, List<LogEvent>> entry : groups.entrySet()) {
            List<LogEvent> window = widestIdentityWindow(entry.getValue());
            long users = window.stream().map(LogEvent::identity).distinct().count();
            if (users >= DISTINCT_USERS) {
                int score = Math.min(100, 82 + (int) users * 3);
                incidents.add(IncidentFactory.create(
                        id(),
                        "Password spraying pattern",
                        Severity.CRITICAL,
                        score,
                        "source=" + entry.getKey(),
                        window
                ));
            }
        }
        return incidents;
    }

    private List<LogEvent> widestIdentityWindow(List<LogEvent> events) {
        List<LogEvent> ordered = events.stream()
                .sorted((left, right) -> left.timestamp().compareTo(right.timestamp()))
                .toList();
        Map<String, Integer> counts = new HashMap<>();
        int start = 0;
        int bestStart = 0;
        int bestEnd = -1;
        int bestDistinct = 0;

        for (int end = 0; end < ordered.size(); end++) {
            counts.merge(ordered.get(end).identity(), 1, Integer::sum);
            while (Duration.between(ordered.get(start).timestamp(), ordered.get(end).timestamp()).compareTo(WINDOW) > 0) {
                String identity = ordered.get(start++).identity();
                counts.computeIfPresent(identity, (key, count) -> count == 1 ? null : count - 1);
            }
            if (counts.size() > bestDistinct || counts.size() == bestDistinct && end - start > bestEnd - bestStart) {
                bestStart = start;
                bestEnd = end;
                bestDistinct = counts.size();
            }
        }
        return bestEnd < 0 ? List.of() : ordered.subList(bestStart, bestEnd + 1);
    }
}

