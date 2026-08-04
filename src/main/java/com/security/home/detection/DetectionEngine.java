package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import com.security.home.entity.SecurityEventType;
import com.security.home.model.NetworkObservation;
import com.security.home.repository.DeviceRepository;
import com.security.home.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DetectionEngine {

    private final Set<String> knownDevices = ConcurrentHashMap.newKeySet();

    private final RulesEngine rulesEngine;
    private final SecurityEventRepository repository;
    private final DeviceRepository deviceRepository;
    private final RiskScoringService riskScoringService;

    public DetectionEngine(RulesEngine rulesEngine,
                           SecurityEventRepository repository,
                           DeviceRepository deviceRepository,
                           RiskScoringService riskScoringService) {
        this.rulesEngine = rulesEngine;
        this.repository = repository;
        this.deviceRepository = deviceRepository;
        this.riskScoringService = riskScoringService;
    }

    public List<SecurityEvent> process(Device device) {
        return processObservation(NetworkObservation.fromDevice(device));
    }

    public List<SecurityEvent> processObservation(NetworkObservation observation) {
        List<SecurityEvent> results = new ArrayList<>();

        if (observation == null) {
            return results;
        }

        String sourceKey = sourceKey(observation.sourceMac(), observation.sourceIp());

        if (knownDevices.add(sourceKey)) {
            registerDevice(observation);
            RiskScoringService.RiskScore risk = riskScoringService.score(
                    SecurityEventType.NEW_DEVICE,
                    observation,
                    35,
                    "fingerprint=" + sourceKey
            );

            SecurityEvent event = new SecurityEvent(
                    SecurityEventType.NEW_DEVICE,
                    risk.severity(),
                    "New device observed in home network: " + displayDevice(observation),
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

            results.add(repository.save(event));
        }

        List<SecurityEvent> ruleEvents = rulesEngine.analyze(observation);

        for (SecurityEvent event : ruleEvents) {
            results.add(repository.save(event));
        }

        return results;
    }

    public List<SecurityEvent> processAttack(Device device) {
        List<SecurityEvent> results = new ArrayList<>();
        List<Integer> scannedPorts = List.of(21, 22, 23, 53, 80, 443, 445, 554, 1883, 5000, 8080, 8443);

        for (Integer port : scannedPorts) {
            results.addAll(processObservation(new NetworkObservation(
                    device.getIp(),
                    device.getMac(),
                    device.getVendor(),
                    "192.168.0.1",
                    port,
                    "TCP",
                    600L,
                    null
            )));
        }

        results.addAll(processObservation(new NetworkObservation(
                device.getIp(),
                device.getMac(),
                device.getVendor(),
                "8.8.8.8",
                53,
                "UDP",
                250L,
                "camera-feed.webhook.site"
        )));

        results.addAll(processObservation(new NetworkObservation(
                device.getIp(),
                device.getMac(),
                device.getVendor(),
                "34.117.59.81",
                443,
                "TLS",
                2_500_000L,
                null
        )));

        return results;
    }

    private void registerDevice(NetworkObservation observation) {
        if (observation.sourceMac() == null || observation.sourceMac().isBlank()) {
            return;
        }

        deviceRepository.findByMacIgnoreCase(observation.sourceMac().trim())
                .orElseGet(() -> deviceRepository.save(new Device(
                        observation.sourceIp(),
                        observation.sourceMac(),
                        observation.vendor()
                )));
    }

    private String sourceKey(String mac, String ip) {
        String normalizedMac = normalize(mac);

        if (!"UNKNOWN".equals(normalizedMac)) {
            return normalizedMac;
        }

        String normalizedIp = normalize(ip);

        return "UNKNOWN".equals(normalizedIp) ? "UNKNOWN-SOURCE" : normalizedIp;
    }

    private String displayDevice(NetworkObservation observation) {
        String vendor = observation.vendor() == null || observation.vendor().isBlank()
                ? "Unknown vendor"
                : observation.vendor().trim();
        String sourceIp = observation.sourceIp() == null || observation.sourceIp().isBlank()
                ? "unknown IP"
                : observation.sourceIp().trim();

        return vendor + " (" + sourceIp + ")";
    }

    private String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.toUpperCase(Locale.ROOT).trim();
    }
}
