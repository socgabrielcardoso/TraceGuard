package io.github.socgabrielcardoso.traceguard.domain;

import java.time.Instant;
import java.util.Objects;

public record Evidence(
        String source,
        long line,
        Instant timestamp,
        String summary
) {
    public Evidence {
        source = source == null ? "" : source;
        timestamp = Objects.requireNonNull(timestamp);
        summary = summary == null ? "" : summary;
    }

    public static Evidence from(LogEvent event) {
        return new Evidence(event.source(), event.line(), event.timestamp(), event.message());
    }
}
