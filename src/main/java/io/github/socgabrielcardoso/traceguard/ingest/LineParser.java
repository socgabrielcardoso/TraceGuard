package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.LogEvent;

import java.time.Clock;
import java.util.Optional;

public interface LineParser {
    boolean supports(String line);

    Optional<LogEvent> parse(String source, long lineNumber, String line, Clock clock);
}
