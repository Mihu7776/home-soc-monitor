package com.security.home.detection;

import com.security.home.entity.EventSeverity;
import com.security.home.entity.SecurityEvent;
import com.security.home.model.SocReport;
import com.security.home.repository.DeviceRepository;
import com.security.home.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class SocReportService {

    private final SecurityEventRepository securityEventRepository;
    private final DeviceRepository deviceRepository;

    public SocReportService(SecurityEventRepository securityEventRepository,
                            DeviceRepository deviceRepository) {
        this.securityEventRepository = securityEventRepository;
        this.deviceRepository = deviceRepository;
    }

    public SocReport buildReport() {
        List<SecurityEvent> events = securityEventRepository.findAll();

        long criticalEvents = countSeverity(events, EventSeverity.CRITICAL);
        long highEvents = countSeverity(events, EventSeverity.HIGH);
        long mediumEvents = countSeverity(events, EventSeverity.MEDIUM);
        long lowEvents = countSeverity(events, EventSeverity.LOW);
        int maxRiskScore = events.stream()
                .map(SecurityEvent::getRiskScore)
                .filter(score -> score != null)
                .max(Integer::compareTo)
                .orElse(0);
        LocalDateTime latestEventAt = events.stream()
                .map(SecurityEvent::getTimestamp)
                .filter(timestamp -> timestamp != null)
                .max(LocalDateTime::compareTo)
                .orElse(null);

        return new SocReport(
                events.size(),
                deviceRepository.count(),
                criticalEvents,
                highEvents,
                mediumEvents,
                lowEvents,
                maxRiskScore,
                mostRiskySource(events),
                latestEventAt,
                group(events, event -> event.getType() == null ? "UNKNOWN" : event.getType().name()),
                group(events, event -> event.getSeverity() == null ? "UNKNOWN" : event.getSeverity().name()),
                group(events, event -> event.getMitreTactic() == null ? "Unmapped" : event.getMitreTactic())
        );
    }

    private long countSeverity(List<SecurityEvent> events, EventSeverity severity) {
        return events.stream()
                .filter(event -> event.getSeverity() == severity)
                .count();
    }

    private String mostRiskySource(List<SecurityEvent> events) {
        return events.stream()
                .filter(event -> event.getRiskScore() != null)
                .max(Comparator.comparing(SecurityEvent::getRiskScore))
                .map(event -> displaySource(event.getSourceIp(), event.getSourceMac()))
                .orElse("none");
    }

    private String displaySource(String sourceIp, String sourceMac) {
        if (sourceIp != null && !sourceIp.isBlank() && sourceMac != null && !sourceMac.isBlank()) {
            return sourceIp + " / " + sourceMac;
        }

        if (sourceIp != null && !sourceIp.isBlank()) {
            return sourceIp;
        }

        if (sourceMac != null && !sourceMac.isBlank()) {
            return sourceMac;
        }

        return "unknown";
    }

    private Map<String, Long> group(List<SecurityEvent> events,
                                    java.util.function.Function<SecurityEvent, String> classifier) {
        return events.stream()
                .collect(Collectors.groupingBy(classifier, LinkedHashMap::new, Collectors.counting()));
    }
}
