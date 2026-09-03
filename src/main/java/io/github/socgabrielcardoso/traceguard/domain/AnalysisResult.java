package io.github.socgabrielcardoso.traceguard.domain;

import java.time.Instant;
import java.util.List;

public record AnalysisResult(
        Instant startedAt,
        Instant finishedAt,
        List<FileDigest> files,
        long processedLines,
        long rejectedLines,
        List<LogEvent> events,
        List<Incident> incidents
) {
    public AnalysisResult {
        files = List.copyOf(files);
        events = List.copyOf(events);
        incidents = incidents.stream().sorted().toList();
    }

    public long durationMillis() {
        return Math.max(0, finishedAt.toEpochMilli() - startedAt.toEpochMilli());
    }
}
