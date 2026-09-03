package io.github.socgabrielcardoso.traceguard.ingest;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.MonthDay;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoField;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OpenSshLineParser implements LineParser {
    private static final Pattern SYSLOG = Pattern.compile("^(?<time>(?:[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}|\\d{4}-\\d{2}-\\d{2}T\\S+))\\s+(?<host>\\S+)\\s+sshd(?:\\[\\d+])?:\\s+(?<message>.+)$");
    private static final Pattern FAILURE = Pattern.compile("Failed (?:password|publickey) for (?:invalid user )?(?<user>\\S+) from (?<ip>[0-9a-fA-F:.]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUCCESS = Pattern.compile("Accepted (?:password|publickey) for (?<user>\\S+) from (?<ip>[0-9a-fA-F:.]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern PAM_FAILURE = Pattern.compile("authentication failure;.*?rhost=(?<ip>\\S+)(?:.*?user=(?<user>\\S+))?", Pattern.CASE_INSENSITIVE);
    private static final DateTimeFormatter SYSLOG_TIME = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("MMM d HH:mm:ss")
            .toFormatter(Locale.ENGLISH);

    @Override
    public boolean supports(String line) {
        return line != null && line.contains("sshd") && SYSLOG.matcher(line).matches();
    }

    @Override
    public Optional<LogEvent> parse(String source, long lineNumber, String line, Clock clock) {
        Matcher syslog = SYSLOG.matcher(line);
        if (!syslog.matches()) {
            return Optional.empty();
        }

        String message = syslog.group("message");
        Matcher failure = FAILURE.matcher(message);
        Matcher success = SUCCESS.matcher(message);
        Matcher pamFailure = PAM_FAILURE.matcher(message);
        EventType type;
        String user = "";
        String sourceIp = "";

        if (failure.find()) {
            type = EventType.AUTH_FAILURE;
            user = failure.group("user");
            sourceIp = failure.group("ip");
        } else if (success.find()) {
            type = EventType.AUTH_SUCCESS;
            user = success.group("user");
            sourceIp = success.group("ip");
        } else if (pamFailure.find()) {
            type = EventType.AUTH_FAILURE;
            user = value(pamFailure, "user");
            sourceIp = value(pamFailure, "ip");
        } else {
            return Optional.empty();
        }

        return Optional.of(new LogEvent(
                source,
                lineNumber,
                parseTimestamp(syslog.group("time"), clock),
                type,
                syslog.group("host"),
                user,
                sourceIp,
                message,
                Map.of("service", "sshd")
        ));
    }

    private static Instant parseTimestamp(String value, Clock clock) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException ignored) {
        }

        ZonedDateTime now = ZonedDateTime.now(clock).withZoneSameInstant(ZoneOffset.UTC);
        DateTimeFormatter formatter = new DateTimeFormatterBuilder()
                .append(SYSLOG_TIME)
                .parseDefaulting(ChronoField.YEAR, now.getYear())
                .toFormatter(Locale.ENGLISH);
        String normalized = value.trim().replaceAll("\\s+", " ");
        LocalDateTime parsed = LocalDateTime.parse(normalized, formatter);
        Instant timestamp = parsed.toInstant(ZoneOffset.UTC);
        if (MonthDay.from(parsed).isAfter(MonthDay.from(now)) && timestamp.isAfter(now.toInstant())) {
            timestamp = parsed.minusYears(1).toInstant(ZoneOffset.UTC);
        }
        return timestamp;
    }

    private static String value(Matcher matcher, String group) {
        try {
            String value = matcher.group(group);
            return value == null ? "" : value;
        } catch (IllegalArgumentException ignored) {
            return "";
        }
    }
}
