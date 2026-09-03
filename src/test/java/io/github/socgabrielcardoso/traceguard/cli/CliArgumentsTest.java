package io.github.socgabrielcardoso.traceguard.cli;

import io.github.socgabrielcardoso.traceguard.domain.Severity;
import io.github.socgabrielcardoso.traceguard.report.ReportFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CliArgumentsTest {
    @Test
    void infersJsonFromOutputName() {
        CliArguments arguments = CliArguments.parse(new String[]{
                "analyze", "logs", "--output", "incidents.json", "--fail-on", "high"
        });

        assertEquals(Command.ANALYZE, arguments.command());
        assertEquals(ReportFormat.JSON, arguments.format());
        assertEquals(Severity.HIGH, arguments.failOn());
    }

    @Test
    void rejectsUnknownOption() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CliArguments.parse(new String[]{"analyze", "auth.log", "--unknown"})
        );
    }
}
