package io.github.socgabrielcardoso.traceguard.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogAnalyzerTest {
    @TempDir
    Path directory;

    @Test
    void analyzesDirectoryAndPreservesSourceIntegrity() throws Exception {
        Path log = directory.resolve("security.log");
        Files.writeString(log, """
                2026-09-03T10:00:00Z event=auth_failure user=admin ip=203.0.113.8 host=dc-01
                2026-09-03T10:01:00Z event=auth_failure user=admin ip=203.0.113.8 host=dc-01
                2026-09-03T10:02:00Z event=auth_failure user=admin ip=203.0.113.8 host=dc-01
                2026-09-03T10:03:00Z event=auth_failure user=admin ip=203.0.113.8 host=dc-01
                2026-09-03T10:04:00Z event=auth_failure user=admin ip=203.0.113.8 host=dc-01
                ignored line
                """);

        var result = new LogAnalyzer().analyze(directory);

        assertEquals(6, result.processedLines());
        assertEquals(1, result.rejectedLines());
        assertEquals(5, result.events().size());
        assertTrue(result.incidents().stream().anyMatch(incident -> incident.ruleId().equals("AUTH-BRUTE-FORCE")));
        assertEquals(64, result.files().get(0).sha256().length());
        assertFalse(result.files().get(0).sha256().isBlank());
    }
}

