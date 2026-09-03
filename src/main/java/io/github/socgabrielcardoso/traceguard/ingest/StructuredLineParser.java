package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class StructuredLineParser implements LineParser {
    private static final Pattern FIELD = Pattern.compile("([@A-Za-z0-9_.-]+)=(\\\"(?:\\\\.|[^\\\"])*\\\"|\\S+)");

    @Override
    public boolean supports(String line) {
        return line != null && line.indexOf('=') > 0;
    }

    @Override
    public Optional<LogEvent> parse(String source, long lineNumber, String line, Clock clock) {
        Map<String, String> fields = fields(line);
        if (fields.isEmpty()) {
            return Optional.empty();
        }

        Instant timestamp = timestamp(line, fields, clock);
        EventType type = EventType.from(first(fields, "event", "event_type", "type", "action"));
        String host = first(fields, "host", "hostname", "device", "computer");
        String user = first(fields, "user", "username", "account", "subject");
        String sourceIp = first(fields, "ip", "src", "src_ip", "source_ip", "client_ip");
        String message = first(fields, "message", "msg", "description", "reason");
        if (message.isBlank()) {
            message = line.trim();
        }

        return Optional.of(new LogEvent(
                source,
                lineNumber,
                timestamp,
                type,
                host,
                user,
                sourceIp,
                message,
                fields
        ));
    }

    private static Map<String, String> fields(String line) {
        Map<String, String> values = new LinkedHashMap<>();
        Matcher matcher = FIELD.matcher(line);
        while (matcher.find()) {
            values.put(matcher.group(1).toLowerCase(Locale.ROOT), unquote(matcher.group(2)));
        }
        return values;
    }

    private static Instant timestamp(String line, Map<String, String> fields, Clock clock) {
        String value = first(fields, "timestamp", "time", "datetime", "@timestamp");
        if (value.isBlank()) {
            int separator = line.indexOf(' ');
            value = separator < 0 ? line : line.substring(0, separator);
        }
        return parseTimestamp(value).orElseGet(clock::instant);
    }

    private static Optional<Instant> parseTimestamp(String value) {
        try {
            return Optional.of(Instant.parse(value));
        } catch (DateTimeParseException ignored) {
        }
        try {
            return Optional.of(OffsetDateTime.parse(value).toInstant());
        } catch (DateTimeParseException ignored) {
        }
        try {
            return Optional.of(LocalDateTime.parse(value).toInstant(ZoneOffset.UTC));
        } catch (DateTimeParseException ignored) {
            return Optional.empty();
        }
    }

    private static String first(Map<String, String> fields, String... names) {
        for (String name : names) {
            String value = fields.get(name);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1)
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\");
        }
        return value;
    }
}
