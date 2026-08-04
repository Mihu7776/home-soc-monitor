package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import com.security.home.entity.SecurityEventType;
import com.security.home.model.NetworkObservation;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RulesEngine {

    private static final long PORT_SCAN_WINDOW_MS = Duration.ofSeconds(10).toMillis();
    private static final long PORT_SCAN_COOLDOWN_MS = Duration.ofSeconds(20).toMillis();
    private static final int PORT_SCAN_DISTINCT_PORTS = 8;

    private static final long EXFIL_WINDOW_MS = Duration.ofMinutes(1).toMillis();
    private static final long EXFIL_COOLDOWN_MS = Duration.ofSeconds(30).toMillis();
    private static final long SINGLE_EXTERNAL_TRANSFER_BYTES = 1_500_000L;
    private static final long WINDOW_EXTERNAL_TRANSFER_BYTES = 5_000_000L;

    private static final Set<String> ROUTER_IPS = Set.of(
            "192.168.0.1",
            "192.168.1.1",
            "10.0.0.1"
    );

    private static final Set<Integer> ADMIN_PORTS = Set.of(22, 23, 80, 443, 8080, 8443);

    private static final List<String> SUSPICIOUS_DNS_PATTERNS = List.of(
            "pastebin",
            "webhook.site",
            "requestbin",
            "ngrok",
            "duckdns",
            "no-ip",
            "dnslog",
            "interactsh",
            "discordapp",
            "raw.githubusercontent"
    );

    private final Map<String, DeviceActivity> activityBySource = new ConcurrentHashMap<>();
    private final RiskScoringService riskScoringService;

    public RulesEngine(RiskScoringService riskScoringService) {
        this.riskScoringService = riskScoringService;
    }

    public List<SecurityEvent> analyze(Device device) {
        return analyze(NetworkObservation.fromDevice(device));
    }

    public List<SecurityEvent> analyze(NetworkObservation observation) {
        List<SecurityEvent> alerts = new ArrayList<>();

        if (observation == null) {
            return alerts;
        }

        long now = System.currentTimeMillis();
        String sourceKey = sourceKey(observation);
        DeviceActivity activity = activityBySource.computeIfAbsent(sourceKey, ignored -> new DeviceActivity());

        detectRouterLoginAttempt(observation, alerts);
        detectSuspiciousDns(observation, alerts);
        detectPortScan(observation, activity, alerts, now);
        detectDataExfiltration(observation, activity, alerts, now);

        return alerts;
    }

    private void detectRouterLoginAttempt(NetworkObservation observation, List<SecurityEvent> alerts) {
        Integer port = observation.destinationPort();

        if (port == null || !ROUTER_IPS.contains(trim(observation.destinationIp())) || !ADMIN_PORTS.contains(port)) {
            return;
        }

        alerts.add(event(
                SecurityEventType.ROUTER_LOGIN_ATTEMPT,
                "Router administration access attempt from " + displayDevice(observation),
                observation,
                isIotDevice(observation.vendor()) ? 68 : 52,
                "destination=" + observation.destinationIp() + ":" + port
        ));
    }

    private void detectSuspiciousDns(NetworkObservation observation, List<SecurityEvent> alerts) {
        String query = normalizeText(observation.dnsQuery());

        if (query == null) {
            return;
        }

        for (String pattern : SUSPICIOUS_DNS_PATTERNS) {
            if (query.contains(pattern)) {
                alerts.add(event(
                        SecurityEventType.SUSPICIOUS_DNS,
                        "Suspicious DNS query from " + displayDevice(observation),
                        observation,
                        62,
                        "dnsQuery=" + observation.dnsQuery() + ", matchedPattern=" + pattern
                ));
                return;
            }
        }
    }

    private void detectPortScan(NetworkObservation observation,
                                DeviceActivity activity,
                                List<SecurityEvent> alerts,
                                long now) {
        Integer port = observation.destinationPort();

        if (port == null || port < 1 || port > 65535) {
            return;
        }

        int distinctPorts = activity.recordPort(now, port);

        if (distinctPorts >= PORT_SCAN_DISTINCT_PORTS && activity.markPortScanAlert(now)) {
            alerts.add(event(
                    SecurityEventType.PORT_SCAN,
                    "Possible port scan from " + displayDevice(observation),
                    observation,
                    70,
                    "distinctPorts=" + distinctPorts + ", windowSeconds=" + (PORT_SCAN_WINDOW_MS / 1000)
            ));
        }
    }

    private void detectDataExfiltration(NetworkObservation observation,
                                        DeviceActivity activity,
                                        List<SecurityEvent> alerts,
                                        long now) {
        long bytesOut = safeBytes(observation.bytesOut());

        if (bytesOut <= 0 || !isExternalDestination(observation.destinationIp())) {
            return;
        }

        long windowBytes = activity.recordExternalTransfer(now, bytesOut);
        boolean largeSingleTransfer = bytesOut >= SINGLE_EXTERNAL_TRANSFER_BYTES;
        boolean largeWindowTransfer = windowBytes >= WINDOW_EXTERNAL_TRANSFER_BYTES;

        if (!isIotDevice(observation.vendor()) || (!largeSingleTransfer && !largeWindowTransfer)) {
            return;
        }

        if (!activity.markExfilAlert(now)) {
            return;
        }

        alerts.add(event(
                SecurityEventType.POSSIBLE_DATA_EXFILTRATION,
                "Possible IoT data exfiltration from " + displayDevice(observation),
                observation,
                windowBytes >= WINDOW_EXTERNAL_TRANSFER_BYTES ? 80 : 72,
                "bytesOut=" + bytesOut + ", windowBytes=" + windowBytes + ", destination=" + observation.destinationIp()
        ));
    }

    private SecurityEvent event(SecurityEventType type,
                                String message,
                                NetworkObservation observation,
                                int baseRiskScore,
                                String evidence) {
        RiskScoringService.RiskScore risk = riskScoringService.score(type, observation, baseRiskScore, evidence);

        return new SecurityEvent(
                type,
                risk.severity(),
                message,
                observation.sourceIp(),
                observation.sourceMac(),
                observation.destinationIp(),
                observation.destinationPort(),
                observation.protocol(),
                observation.bytesOut(),
                risk.score(),
                risk.mitreTactic(),
                risk.mitreTechnique(),
                risk.evidence()
        );
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
        String text = trim(value);

        if (text == null) {
            return null;
        }

        String[] parts = text.split("\\.");

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
        String normalized = normalizeText(vendor);

        if (normalized == null) {
            return false;
        }

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

    private String sourceKey(NetworkObservation observation) {
        String mac = normalizeText(observation.sourceMac());

        if (mac != null) {
            return mac;
        }

        String ip = normalizeText(observation.sourceIp());

        return ip == null ? "unknown-source" : ip;
    }

    private String displayDevice(NetworkObservation observation) {
        String vendor = trim(observation.vendor());
        String sourceIp = trim(observation.sourceIp());

        if (vendor != null && sourceIp != null) {
            return vendor + " (" + sourceIp + ")";
        }

        if (vendor != null) {
            return vendor;
        }

        return sourceIp == null ? "unknown device" : sourceIp;
    }

    private long safeBytes(Long bytesOut) {
        return bytesOut == null ? 0L : Math.max(bytesOut, 0L);
    }

    private String normalizeText(String value) {
        String trimmed = trim(value);

        return trimmed == null ? null : trimmed.toLowerCase(Locale.ROOT);
    }

    private String trim(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();

        return trimmed.isEmpty() ? null : trimmed;
    }

    private static final class DeviceActivity {
        private final Deque<PortTouch> portTouches = new ArrayDeque<>();
        private final Deque<TransferSample> externalTransfers = new ArrayDeque<>();
        private long lastPortScanAlertAt;
        private long lastExfilAlertAt;

        synchronized int recordPort(long now, int port) {
            portTouches.addLast(new PortTouch(now, port));
            removeOldPortTouches(now);

            Set<Integer> distinctPorts = new HashSet<>();

            for (PortTouch touch : portTouches) {
                distinctPorts.add(touch.port());
            }

            return distinctPorts.size();
        }

        synchronized long recordExternalTransfer(long now, long bytes) {
            externalTransfers.addLast(new TransferSample(now, bytes));
            removeOldTransfers(now);

            long sum = 0L;

            for (TransferSample sample : externalTransfers) {
                sum += sample.bytes();
            }

            return sum;
        }

        synchronized boolean markPortScanAlert(long now) {
            if (now - lastPortScanAlertAt < PORT_SCAN_COOLDOWN_MS) {
                return false;
            }

            lastPortScanAlertAt = now;
            return true;
        }

        synchronized boolean markExfilAlert(long now) {
            if (now - lastExfilAlertAt < EXFIL_COOLDOWN_MS) {
                return false;
            }

            lastExfilAlertAt = now;
            return true;
        }

        private void removeOldPortTouches(long now) {
            while (!portTouches.isEmpty() && now - portTouches.peekFirst().timestamp() > PORT_SCAN_WINDOW_MS) {
                portTouches.removeFirst();
            }
        }

        private void removeOldTransfers(long now) {
            while (!externalTransfers.isEmpty() && now - externalTransfers.peekFirst().timestamp() > EXFIL_WINDOW_MS) {
                externalTransfers.removeFirst();
            }
        }
    }

    private record PortTouch(long timestamp, int port) {
    }

    private record TransferSample(long timestamp, long bytes) {
    }
}
