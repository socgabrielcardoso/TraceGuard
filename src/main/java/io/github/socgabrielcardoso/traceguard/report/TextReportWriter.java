package io.github.socgabrielcardoso.traceguard.report;

import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;
import io.github.socgabrielcardoso.traceguard.domain.Evidence;
import io.github.socgabrielcardoso.traceguard.domain.FileDigest;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

public final class TextReportWriter implements ReportWriter {
    @Override
    public String write(AnalysisResult result) {
        StringBuilder output = new StringBuilder();
        output.append("TRACEGUARD\n");
        output.append("Started: ").append(result.startedAt()).append('\n');
        output.append("Duration: ").append(result.durationMillis()).append(" ms\n");
        output.append("Files: ").append(result.files().size()).append('\n');
        output.append("Lines: ").append(result.processedLines()).append('\n');
        output.append("Rejected: ").append(result.rejectedLines()).append('\n');
        output.append("Events: ").append(result.events().size()).append('\n');
        output.append("Incidents: ").append(result.incidents().size()).append('\n');
        output.append("Critical: ").append(count(result, Severity.CRITICAL)).append('\n');
        output.append("High: ").append(count(result, Severity.HIGH)).append("\n\n");

        output.append("SOURCE INTEGRITY\n");
        for (FileDigest file : result.files()) {
            output.append(file.sha256()).append("  ").append(file.path())
                    .append("  ").append(file.bytes()).append(" bytes\n");
        }

        if (result.incidents().isEmpty()) {
            output.append("\nNo incidents detected.\n");
            return output.toString();
        }

        output.append("\nINCIDENTS\n");
        for (Incident incident : result.incidents()) {
            output.append('\n')
                    .append('[').append(incident.severity()).append("] ")
                    .append(incident.id()).append("  ").append(incident.title()).append('\n');
            output.append("Rule: ").append(incident.ruleId()).append('\n');
            output.append("Score: ").append(incident.score()).append("/100\n");
            output.append("Entity: ").append(incident.entity()).append('\n');
            output.append("Window: ").append(incident.firstSeen()).append(" -> ")
                    .append(incident.lastSeen()).append('\n');
            output.append("Evidence:\n");
            for (Evidence evidence : incident.evidence()) {
                output.append("  ").append(evidence.source()).append(':').append(evidence.line())
                        .append("  ").append(evidence.timestamp()).append("  ")
                        .append(singleLine(evidence.summary())).append('\n');
            }
        }
        return output.toString();
    }

    private long count(AnalysisResult result, Severity severity) {
        return result.incidents().stream().filter(incident -> incident.severity() == severity).count();
    }

    private String singleLine(String value) {
        return value.replace('\n', ' ').replace('\r', ' ');
    }
}

