package io.github.socgabrielcardoso.traceguard.domain;

import java.util.Locale;

public enum Severity {
    LOW(25),
    MEDIUM(50),
    HIGH(75),
    CRITICAL(100);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int weight() {
        return weight;
    }

    public static Severity from(String value) {
        return value == null ? LOW : valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
}
