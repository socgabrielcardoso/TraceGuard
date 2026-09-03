package io.github.socgabrielcardoso.traceguard.domain;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record LogEvent(
        String source,
        long line,
        Instant timestamp,
        EventType type,
        String host,
        String user,
        String sourceIp,
        String message,
        Map<String, String> attributes
) {
    public LogEvent {
        source = clean(source);
        timestamp = Objects.requireNonNull(timestamp);
        type = Objects.requireNonNullElse(type, EventType.UNKNOWN);
        host = clean(host);
        user = clean(user);
        sourceIp = clean(sourceIp);
        message = clean(message);
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public String identity() {
        if (!user.isBlank()) {
            return user.toLowerCase();
        }
        if (!sourceIp.isBlank()) {
            return sourceIp;
        }
        return "unknown";
    }

    public String origin() {
        return sourceIp.isBlank() ? "unknown" : sourceIp;
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }
}
