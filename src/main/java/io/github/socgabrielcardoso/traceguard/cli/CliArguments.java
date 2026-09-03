package io.github.socgabrielcardoso.traceguard.cli;

import io.github.socgabrielcardoso.traceguard.domain.Severity;
import io.github.socgabrielcardoso.traceguard.report.ReportFormat;

import java.nio.file.Path;

public record CliArguments(
        Command command,
        Path input,
        Path output,
        ReportFormat format,
        Severity failOn
) {
    public static CliArguments parse(String[] arguments) {
        if (arguments.length == 0) {
            return basic(Command.HELP);
        }

        return switch (arguments[0]) {
            case "analyze", "scan" -> analyze(arguments);
            case "rules" -> basic(Command.RULES);
            case "version", "--version", "-v" -> basic(Command.VERSION);
            case "help", "--help", "-h" -> basic(Command.HELP);
            default -> throw new IllegalArgumentException("Unknown command: " + arguments[0]);
        };
    }

    private static CliArguments analyze(String[] arguments) {
        Path input = null;
        Path output = null;
        ReportFormat format = null;
        Severity failOn = null;

        for (int index = 1; index < arguments.length; index++) {
            String argument = arguments[index];
            if (argument.equals("--format")) {
                format = ReportFormat.from(value(arguments, ++index, "--format"));
            } else if (argument.startsWith("--format=")) {
                format = ReportFormat.from(argument.substring("--format=".length()));
            } else if (argument.equals("--output") || argument.equals("-o")) {
                output = Path.of(value(arguments, ++index, argument));
            } else if (argument.startsWith("--output=")) {
                output = Path.of(argument.substring("--output=".length()));
            } else if (argument.equals("--fail-on")) {
                failOn = Severity.from(value(arguments, ++index, "--fail-on"));
            } else if (argument.startsWith("--fail-on=")) {
                failOn = Severity.from(argument.substring("--fail-on=".length()));
            } else if (argument.equals("--help") || argument.equals("-h")) {
                return basic(Command.HELP);
            } else if (argument.startsWith("-")) {
                throw new IllegalArgumentException("Unknown option: " + argument);
            } else if (input == null) {
                input = Path.of(argument);
            } else {
                throw new IllegalArgumentException("Only one input path is accepted");
            }
        }

        if (input == null) {
            throw new IllegalArgumentException("Missing input path");
        }
        if (format == null) {
            format = inferFormat(output);
        }
        return new CliArguments(Command.ANALYZE, input, output, format, failOn);
    }

    private static CliArguments basic(Command command) {
        return new CliArguments(command, null, null, ReportFormat.TEXT, null);
    }

    private static String value(String[] arguments, int index, String option) {
        if (index >= arguments.length || arguments[index].startsWith("--")) {
            throw new IllegalArgumentException("Missing value for " + option);
        }
        return arguments[index];
    }

    private static ReportFormat inferFormat(Path output) {
        if (output != null && output.getFileName().toString().toLowerCase().endsWith(".json")) {
            return ReportFormat.JSON;
        }
        return ReportFormat.TEXT;
    }
}

