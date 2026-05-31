package com.security.home.detection;

import com.security.home.entity.EventSeverity;
import com.security.home.entity.SecurityEventType;
import com.security.home.model.NetworkObservation;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScoringServiceTest {

    private final RiskScoringService riskScoringService = new RiskScoringService();

    @Test
    void raisesRiskForIotExfiltrationToExternalDestination() {
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

        RiskScoringService.RiskScore risk = riskScoringService.score(
                SecurityEventType.POSSIBLE_DATA_EXFILTRATION,
                observation,
                72,
                "bytesOut=2500000"
        );

        assertThat(risk.score()).isEqualTo(100);
        assertThat(risk.severity()).isEqualTo(EventSeverity.CRITICAL);
        assertThat(risk.mitreTactic()).isEqualTo("Exfiltration");
        assertThat(risk.evidence()).contains("iotDevice=true", "externalDestination=true");
    }
}
