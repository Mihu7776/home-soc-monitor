package com.security.home.detection;

import com.security.home.entity.EventSeverity;
import com.security.home.entity.SecurityEventType;
import com.security.home.model.NetworkObservation;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class RiskScoringService {

    public RiskScore score(SecurityEventType type,
                           NetworkObservation observation,
                           int baseScore,
                           String evidence) {
        int score = baseScore;
        StringBuilder factors = new StringBuilder(evidence == null ? "" : evidence);

        if (isIotDevice(observation.vendor())) {
            score += 8;
            appendFactor(factors, "iotDevice=true");
        }

        if (isExternalDestination(observation.destinationIp())) {
            score += 10;
            appendFactor(factors, "externalDestination=true");
        }

        if (safeBytes(observation.bytesOut()) >= 1_500_000L) {
            score += 10;
            appendFactor(factors, "largeOutboundTransfer=true");
        }

        if (isRouterAdministrationTarget(observation.destinationIp(), observation.destinationPort())) {
            score += 8;
            appendFactor(factors, "routerAdminTarget=true");
        }

        score = Math.min(score, 100);

        MitreMapping mitre = mitreMapping(type);

        return new RiskScore(
                score,
                severityFor(score),
                factors.toString(),
                mitre.tactic(),
                mitre.technique()
        );
    }

    private EventSeverity severityFor(int score) {
        if (score >= 90) {
            return EventSeverity.CRITICAL;
        }

        if (score >= 70) {
            return EventSeverity.HIGH;
        }

        if (score >= 40) {
            return EventSeverity.MEDIUM;
        }

        return EventSeverity.LOW;
    }

    private MitreMapping mitreMapping(SecurityEventType type) {
        return switch (type) {
            case NEW_DEVICE -> new MitreMapping("Discovery", "T1016 System Network Configuration Discovery");
            case PORT_SCAN -> new MitreMapping("Discovery", "T1046 Network Service Discovery");
            case SUSPICIOUS_DNS -> new MitreMapping("Command and Control", "T1071.004 DNS");
            case POSSIBLE_DATA_EXFILTRATION -> new MitreMapping("Exfiltration", "T1041 Exfiltration Over C2 Channel");
            case ROUTER_LOGIN_ATTEMPT -> new MitreMapping("Credential Access", "T1110 Brute Force");
            case SURICATA_ALERT -> new MitreMapping("Detection", "External IDS alert");
        };
    }

    private boolean isRouterAdministrationTarget(String destinationIp, Integer destinationPort) {
        if (destinationIp == null || destinationPort == null) {
            return false;
        }

        String ip = destinationIp.trim();

        return ("192.168.0.1".equals(ip) || "192.168.1.1".equals(ip) || "10.0.0.1".equals(ip))
                && (destinationPort == 22
                || destinationPort == 23
                || destinationPort == 80
                || destinationPort == 443
                || destinationPort == 8080
                || destinationPort == 8443);
    }

    private boolean isExternalDestination(String destinationIp) {
        int[] ip = parseIpv4(destinationIp);

        if (ip == null) {
            return false;
        }

        if (ip[0] == 10 || ip[0] == 127 || ip[0] == 0) {
            return false;
        }

        if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
            return false;
        }

        if (ip[0] == 192 && ip[1] == 168) {
            return false;
        }

        if (ip[0] == 169 && ip[1] == 254) {
            return false;
        }

        return ip[0] < 224;
    }

    private int[] parseIpv4(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        String[] parts = value.trim().split("\\.");

        if (parts.length != 4) {
            return null;
        }

        int[] parsed = new int[4];

        for (int i = 0; i < parts.length; i++) {
            try {
                parsed[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException ex) {
                return null;
            }

            if (parsed[i] < 0 || parsed[i] > 255) {
                return null;
            }
        }

        return parsed;
    }

    private boolean isIotDevice(String vendor) {
        if (vendor == null || vendor.isBlank()) {
            return false;
        }

        String normalized = vendor.toLowerCase(Locale.ROOT);

        return normalized.contains("iot")
                || normalized.contains("camera")
                || normalized.contains("smart")
                || normalized.contains("tv")
                || normalized.contains("plug")
                || normalized.contains("bulb")
                || normalized.contains("sensor")
                || normalized.contains("thermostat")
                || normalized.contains("doorbell");
    }

    private long safeBytes(Long bytesOut) {
        return bytesOut == null ? 0L : Math.max(bytesOut, 0L);
    }

    private void appendFactor(StringBuilder factors, String factor) {
        if (!factors.isEmpty()) {
            factors.append(", ");
        }

        factors.append(factor);
    }

    public record RiskScore(
            int score,
            EventSeverity severity,
            String evidence,
            String mitreTactic,
            String mitreTechnique
    ) {
    }

    private record MitreMapping(String tactic, String technique) {
    }
}
