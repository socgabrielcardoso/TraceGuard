package io.github.socgabrielcardoso.traceguard.report;

import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;
import io.github.socgabrielcardoso.traceguard.domain.FileDigest;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonReportWriterTest {
    @Test
    void createsMachineReadableSummary() {
        Instant time = Instant.parse("2026-09-03T10:00:00Z");
        AnalysisResult result = new AnalysisResult(
                time,
                time.plusMillis(12),
                List.of(new FileDigest("audit\"file.log", 42, "abc123")),
                8,
                1,
                List.of(),
                List.of()
        );

        String json = new JsonReportWriter().write(result);

        assertTrue(json.startsWith("{\n"));
        assertTrue(json.contains("\"durationMs\": 12"));
        assertTrue(json.contains("audit\\\"file.log"));
        assertTrue(json.endsWith("}\n"));
    }
}

