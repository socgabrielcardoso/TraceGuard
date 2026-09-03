package io.github.socgabrielcardoso.traceguard.report;

import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;
import io.github.socgabrielcardoso.traceguard.domain.Evidence;
import io.github.socgabrielcardoso.traceguard.domain.FileDigest;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.util.List;

public final class JsonReportWriter implements ReportWriter {
    @Override
    public String write(AnalysisResult result) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        field(json, "tool", "TraceGuard", 1, true);
        field(json, "generatedAt", result.finishedAt().toString(), 1, true);
        number(json, "durationMs", result.durationMillis(), 1, true);
        json.append("  \"summary\": {\n");
        number(json, "files", result.files().size(), 2, true);
        number(json, "lines", result.processedLines(), 2, true);
        number(json, "rejected", result.rejectedLines(), 2, true);
        number(json, "events", result.events().size(), 2, true);
        number(json, "incidents", result.incidents().size(), 2, true);
        number(json, "critical", count(result, Severity.CRITICAL), 2, true);
        number(json, "high", count(result, Severity.HIGH), 2, false);
        json.append("  },\n");
        json.append("  \"files\": [\n");
        appendFiles(json, result.files());
        json.append("  ],\n");
        json.append("  \"incidents\": [\n");
        appendIncidents(json, result.incidents());
        json.append("  ]\n");
        json.append("}\n");
        return json.toString();
    }

    private void appendFiles(StringBuilder json, List<FileDigest> files) {
        for (int index = 0; index < files.size(); index++) {
            FileDigest file = files.get(index);
            json.append("    {\n");
            field(json, "path", file.path(), 3, true);
            number(json, "bytes", file.bytes(), 3, true);
            field(json, "sha256", file.sha256(), 3, false);
            json.append("    }").append(index + 1 < files.size() ? "," : "").append('\n');
        }
    }

    private void appendIncidents(StringBuilder json, List<Incident> incidents) {
        for (int index = 0; index < incidents.size(); index++) {
            Incident incident = incidents.get(index);
            json.append("    {\n");
            field(json, "id", incident.id(), 3, true);
            field(json, "rule", incident.ruleId(), 3, true);
            field(json, "title", incident.title(), 3, true);
            field(json, "severity", incident.severity().name(), 3, true);
            number(json, "score", incident.score(), 3, true);
            field(json, "entity", incident.entity(), 3, true);
            field(json, "firstSeen", incident.firstSeen().toString(), 3, true);
            field(json, "lastSeen", incident.lastSeen().toString(), 3, true);
            json.append("      \"evidence\": [\n");
            appendEvidence(json, incident.evidence());
            json.append("      ]\n");
            json.append("    }").append(index + 1 < incidents.size() ? "," : "").append('\n');
        }
    }

    private void appendEvidence(StringBuilder json, List<Evidence> evidence) {
        for (int index = 0; index < evidence.size(); index++) {
            Evidence item = evidence.get(index);
            json.append("        {\n");
            field(json, "source", item.source(), 5, true);
            number(json, "line", item.line(), 5, true);
            field(json, "timestamp", item.timestamp().toString(), 5, true);
            field(json, "summary", item.summary(), 5, false);
            json.append("        }").append(index + 1 < evidence.size() ? "," : "").append('\n');
        }
    }

    private long count(AnalysisResult result, Severity severity) {
        return result.incidents().stream().filter(incident -> incident.severity() == severity).count();
    }

    private void field(StringBuilder json, String name, String value, int indent, boolean comma) {
        json.append("  ".repeat(indent))
                .append(quote(name)).append(": ").append(quote(value))
                .append(comma ? "," : "").append('\n');
    }

    private void number(StringBuilder json, String name, long value, int indent, boolean comma) {
        json.append("  ".repeat(indent))
                .append(quote(name)).append(": ").append(value)
                .append(comma ? "," : "").append('\n');
    }

    private String quote(String value) {
        StringBuilder escaped = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }
        return escaped.append('\"').toString();
    }
}
