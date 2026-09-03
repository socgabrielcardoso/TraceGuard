package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.Evidence;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

final class IncidentFactory {
    private IncidentFactory() {
    }

    static Incident create(
            String ruleId,
            String title,
            Severity severity,
            int score,
            String entity,
            List<LogEvent> events
    ) {
        List<LogEvent> ordered = events.stream()
                .sorted((left, right) -> left.timestamp().compareTo(right.timestamp()))
                .toList();
        String seed = ruleId + '|' + entity + '|' + ordered.get(0).timestamp();
        String id = "TG-" + digest(seed).substring(0, 12).toUpperCase();
        return new Incident(
                id,
                ruleId,
                title,
                severity,
                score,
                entity,
                ordered.get(0).timestamp(),
                ordered.get(ordered.size() - 1).timestamp(),
                ordered.stream().map(Evidence::from).toList()
        );
    }

    private static String digest(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}

