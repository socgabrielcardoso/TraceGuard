package io.github.socgabrielcardoso.traceguard.report;

import java.util.Locale;

public enum ReportFormat {
    TEXT,
    JSON;

    public static ReportFormat from(String value) {
        return valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
}

