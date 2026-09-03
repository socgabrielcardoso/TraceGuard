package io.github.socgabrielcardoso.traceguard.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record Incident(
        String id,
        String ruleId,
        String title,
        Severity severity,
        int score,
        String entity,
        Instant firstSeen,
        Instant lastSeen,
        List<Evidence> evidence
) implements Comparable<Incident> {
    public Incident {
        id = Objects.requireNonNull(id);
        ruleId = Objects.requireNonNull(ruleId);
        title = Objects.requireNonNull(title);
        severity = Objects.requireNonNull(severity);
        score = Math.max(0, Math.min(100, score));
        entity = entity == null ? "unknown" : entity;
        firstSeen = Objects.requireNonNull(firstSeen);
        lastSeen = Objects.requireNonNull(lastSeen);
        evidence = List.copyOf(evidence);
    }

    @Override
    public int compareTo(Incident other) {
        int severityOrder = Integer.compare(other.severity.weight(), severity.weight());
        if (severityOrder != 0) {
            return severityOrder;
        }
        int scoreOrder = Integer.compare(other.score, score);
        if (scoreOrder != 0) {
            return scoreOrder;
        }
        return firstSeen.compareTo(other.firstSeen);
    }
}
