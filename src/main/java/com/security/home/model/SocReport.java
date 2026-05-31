package com.security.home.model;

import java.time.LocalDateTime;
import java.util.Map;

public record SocReport(
        long totalEvents,
        long totalDevices,
        long criticalEvents,
        long highEvents,
        long mediumEvents,
        long lowEvents,
        int maxRiskScore,
        String mostRiskySource,
        LocalDateTime latestEventAt,
        Map<String, Long> eventsByType,
        Map<String, Long> eventsBySeverity,
        Map<String, Long> eventsByMitreTactic
) {
}
