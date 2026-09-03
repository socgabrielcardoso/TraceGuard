package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.EventType;
import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;
import io.github.socgabrielcardoso.traceguard.domain.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class SuspiciousProcessRule implements DetectionRule {
    private static final Map<String, Integer> SIGNALS = Map.of(
            "-encodedcommand", 4,
            "frombase64string", 4,
            "invoke-expression", 3,
            "downloadstring", 3,
            "windowstyle hidden", 2,
            "executionpolicy bypass", 2,
            "-enc ", 3,
            "iex(", 3
    );

    @Override
    public String id() {
        return "PROCESS-SUSPICIOUS-COMMAND";
    }

    @Override
    public List<Incident> detect(List<LogEvent> events) {
        List<Incident> incidents = new ArrayList<>();
        for (LogEvent event : events) {
            if (event.type() != EventType.PROCESS_EXECUTION) {
                continue;
            }
            String command = command(event).toLowerCase(Locale.ROOT);
            int signal = SIGNALS.entrySet().stream()
                    .filter(entry -> command.contains(entry.getKey()))
                    .mapToInt(Map.Entry::getValue)
                    .sum();
            if (signal >= 3) {
                int score = Math.min(97, 70 + signal * 3);
                Severity severity = score >= 90 ? Severity.CRITICAL : Severity.HIGH;
                String entity = event.host().isBlank() ? "host=unknown" : "host=" + event.host();
                incidents.add(IncidentFactory.create(
                        id(),
                        "Suspicious process command line",
                        severity,
                        score,
                        entity,
                        List.of(event)
                ));
            }
        }
        return incidents;
    }

    private String command(LogEvent event) {
        for (String key : List.of("command_line", "commandline", "cmd", "process_command_line")) {
            String value = event.attributes().get(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return event.message();
    }
}

