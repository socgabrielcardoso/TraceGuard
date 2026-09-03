package io.github.socgabrielcardoso.traceguard.cli;

import io.github.socgabrielcardoso.traceguard.domain.AnalysisResult;
import io.github.socgabrielcardoso.traceguard.domain.Severity;
import io.github.socgabrielcardoso.traceguard.report.ReportWriter;
import io.github.socgabrielcardoso.traceguard.service.LogAnalyzer;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class TraceGuardApp {
    private static final int INCIDENTS_FOUND = 2;
    private static final int USAGE_ERROR = 64;
    private static final int IO_ERROR = 74;

    private final PrintStream out;
    private final PrintStream err;
    private final LogAnalyzer analyzer;

    public TraceGuardApp(PrintStream out, PrintStream err) {
        this(out, err, new LogAnalyzer());
    }

    public TraceGuardApp(PrintStream out, PrintStream err, LogAnalyzer analyzer) {
        this.out = out;
        this.err = err;
        this.analyzer = analyzer;
    }

    public int run(String[] arguments) {
        try {
            CliArguments options = CliArguments.parse(arguments);
            return switch (options.command()) {
                case ANALYZE -> analyze(options);
                case RULES -> rules();
                case VERSION -> version();
                case HELP -> help();
            };
        } catch (IllegalArgumentException exception) {
            err.println("traceguard: " + exception.getMessage());
            err.println("Run 'traceguard help' for usage.");
            return USAGE_ERROR;
        } catch (IOException exception) {
            err.println("traceguard: " + exception.getMessage());
            return IO_ERROR;
        }
    }

    private int analyze(CliArguments options) throws IOException {
        AnalysisResult result = analyzer.analyze(options.input());
        String report = ReportWriter.forFormat(options.format()).write(result);
        if (options.output() == null) {
            out.print(report);
        } else {
            write(options.output(), report);
            out.println("Report written to " + options.output().toAbsolutePath().normalize());
        }
        return reachedThreshold(result, options.failOn()) ? INCIDENTS_FOUND : 0;
    }

    private int rules() {
        analyzer.ruleIds().forEach(out::println);
        return 0;
    }

    private int version() {
        out.println("TraceGuard 1.0.0");
        return 0;
    }

    private int help() {
        out.print("""
                TraceGuard investigates logs and creates prioritized incidents.

                Usage:
                  traceguard analyze <path> [--format text|json] [--output <file>] [--fail-on <severity>]
                  traceguard rules
                  traceguard version

                Input:
                  OpenSSH authentication logs
                  Structured lines with ISO timestamp and key=value fields

                Examples:
                  traceguard analyze auth.log
                  traceguard analyze logs --format json --output incidents.json
                  traceguard analyze auth.log --fail-on high
                """);
        return 0;
    }

    private boolean reachedThreshold(AnalysisResult result, Severity threshold) {
        return threshold != null && result.incidents().stream()
                .anyMatch(incident -> incident.severity().weight() >= threshold.weight());
    }

    private void write(Path output, String report) throws IOException {
        Path target = output.toAbsolutePath().normalize();
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Path temporary = Files.createTempFile(parent, ".traceguard-", ".tmp");
        try {
            Files.writeString(temporary, report, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ignored) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }
}

