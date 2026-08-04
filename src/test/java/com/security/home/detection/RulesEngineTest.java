package com.security.home.detection;

import com.security.home.entity.SecurityEvent;
import com.security.home.entity.SecurityEventType;
import com.security.home.detection.dns.DnsQueryParser;
import com.security.home.model.NetworkObservation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RulesEngineTest {

    private final RulesEngine rulesEngine = new RulesEngine(new RiskScoringService(), new DnsQueryParser());

    @Test
    void detectsLargeExternalTransferFromIotDevice() {
        NetworkObservation observation = new NetworkObservation(
                "192.168.0.14",
                "AA:BB:CC:05",
                "IoT Camera",
                "34.117.59.81",
                443,
                "TLS",
                2_500_000L,
                null
        );

        List<SecurityEvent> events = rulesEngine.analyze(observation);

        assertThat(events)
                .anyMatch(event -> event.getType() == SecurityEventType.POSSIBLE_DATA_EXFILTRATION
                        && event.getRiskScore() >= 90
                        && "Exfiltration".equals(event.getMitreTactic()));
    }

    @Test
    void ignoresLargeTransferInsideLanAsExfiltration() {
        NetworkObservation observation = new NetworkObservation(
                "192.168.0.14",
                "AA:BB:CC:05",
                "IoT Camera",
                "192.168.0.20",
                443,
                "TLS",
                10_000_000L,
                null
        );

        List<SecurityEvent> events = rulesEngine.analyze(observation);

        assertThat(events)
                .noneMatch(event -> event.getType() == SecurityEventType.POSSIBLE_DATA_EXFILTRATION);
    }

    @Test
    void detectsPortScanAfterManyDistinctPorts() {
        List<SecurityEvent> latestEvents = List.of();

        for (int port : List.of(21, 22, 23, 53, 80, 443, 554, 8080)) {
            latestEvents = rulesEngine.analyze(new NetworkObservation(
                    "192.168.0.13",
                    "AA:BB:CC:04",
                    "Smart TV",
                    "192.168.0.1",
                    port,
                    "TCP",
                    600L,
                    null
            ));
        }

        assertThat(latestEvents)
                .anyMatch(event -> event.getType() == SecurityEventType.PORT_SCAN);
    }

    @Test
    void detectsSuspiciousDnsQuery() {
        NetworkObservation observation = new NetworkObservation(
                "192.168.0.14",
                "AA:BB:CC:05",
                "IoT Camera",
                "8.8.8.8",
                53,
                "UDP",
                200L,
                "camera-feed.webhook.site"
        );

        List<SecurityEvent> events = rulesEngine.analyze(observation);

        assertThat(events)
                .anyMatch(event -> event.getType() == SecurityEventType.SUSPICIOUS_DNS);
    }

    @Test
    void detectsNormalizedSuspiciousDnsQuery() {
        NetworkObservation observation = new NetworkObservation(
                "192.168.0.14",
                "AA:BB:CC:05",
                "IoT Camera",
                "8.8.8.8",
                53,
                "UDP",
                200L,
                "  Camera-Feed.WebHook.Site. "
        );

        List<SecurityEvent> events = rulesEngine.analyze(observation);

        assertThat(events)
                .anyMatch(event -> event.getType() == SecurityEventType.SUSPICIOUS_DNS
                        && event.getEvidence().contains("dnsQuery=camera-feed.webhook.site")
                        && event.getEvidence().contains("baseDomain=webhook.site"));
    }
}
