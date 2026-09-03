package io.github.socgabrielcardoso.traceguard.report;

import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;

public interface ReportWriter {
    String write(AnalysisResult result);

    static ReportWriter forFormat(ReportFormat format) {
        return switch (format) {
            case TEXT -> new TextReportWriter();
            case JSON -> new JsonReportWriter();
        };
    }
}

