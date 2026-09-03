package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;

import java.util.List;

public final class RuleEngine {
    private final List<DetectionRule> rules;

    public RuleEngine(List<DetectionRule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static RuleEngine defaults() {
        return new RuleEngine(List.of(
                new BruteForceRule(),
                new PasswordSprayRule(),
                new SuccessAfterFailuresRule(),
                new SensitiveChangeRule(),
                new SuspiciousProcessRule()
        ));
    }

    public List<Incident> evaluate(List<LogEvent> events) {
        return rules.stream()
                .flatMap(rule -> rule.detect(events).stream())
                .sorted()
                .toList();
    }

    public List<String> ruleIds() {
        return rules.stream().map(DetectionRule::id).toList();
    }
}
