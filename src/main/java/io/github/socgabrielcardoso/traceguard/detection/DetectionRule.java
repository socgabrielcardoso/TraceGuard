package io.github.socgabrielcardoso.traceguard.detection;

import io.github.socgabrielcardoso.traceguard.domain.Incident;
import io.github.socgabrielcardoso.traceguard.domain.LogEvent;

import java.util.List;

public interface DetectionRule {
    String id();

    List<Incident> detect(List<LogEvent> events);
}

