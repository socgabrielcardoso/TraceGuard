package io.github.socgabrielcardoso.traceguard.service;

import io.github.socgabrielcardoso.traceguard.detection.RuleEngine;
import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;
import io.github.socgabrielcardoso.traceguard.domain.FileDigest;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.ingest.LineParser;
import io.github.socgabrielcardoso.traceguard.ingest.OpenSshLineParser;
import io.github.socgabrielcardoso.traceguard.ingest.StructuredLineParser;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class LogAnalyzer {
    private static final int MAX_LINE_LENGTH = 1_000_000;

    private final Clock clock;
    private final RuleEngine ruleEngine;
    private final List<LineParser> parsers;

    public LogAnalyzer() {
        this(Clock.systemUTC(), RuleEngine.defaults(), List.of(
                new OpenSshLineParser(),
                new StructuredLineParser()
        ));
    }

    public LogAnalyzer(Clock clock, RuleEngine ruleEngine, List<LineParser> parsers) {
        this.clock = clock;
        this.ruleEngine = ruleEngine;
        this.parsers = List.copyOf(parsers);
    }

    public AnalysisResult analyze(Path input) throws IOException {
        Instant startedAt = clock.instant();
        List<Path> paths = InputFiles.discover(input);
        if (paths.isEmpty()) {
            throw new IOException("No supported log files found in: " + input);
        }

        List<FileDigest> digests = new ArrayList<>();
        List<LogEvent> events = new ArrayList<>();
        long processedLines = 0;
        long rejectedLines = 0;

        for (Path path : paths) {
            String source = InputFiles.display(input, path);
            digests.add(new FileDigest(source, Files.size(path), FileHasher.sha256(path)));
            try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                String line;
                long lineNumber = 0;
                while ((line = reader.readLine()) != null) {
                    lineNumber++;
                    processedLines++;
                    if (line.isBlank()) {
                        continue;
                    }
                    if (line.length() > MAX_LINE_LENGTH) {
                        rejectedLines++;
                        continue;
                    }
                    Optional<LogEvent> parsed = parse(source, lineNumber, line);
                    if (parsed.isPresent()) {
                        events.add(parsed.get());
                    } else {
                        rejectedLines++;
                    }
                }
            }
        }

        events.sort((left, right) -> left.timestamp().compareTo(right.timestamp()));
        return new AnalysisResult(
                startedAt,
                clock.instant(),
                digests,
                processedLines,
                rejectedLines,
                events,
                ruleEngine.evaluate(events)
        );
    }

    public List<String> ruleIds() {
        return ruleEngine.ruleIds();
    }

    private Optional<LogEvent> parse(String source, long lineNumber, String line) {
        for (LineParser parser : parsers) {
            if (parser.supports(line)) {
                Optional<LogEvent> event = parser.parse(source, lineNumber, line, clock);
                if (event.isPresent()) {
                    return event;
                }
            }
        }
        return Optional.empty();
    }
}
