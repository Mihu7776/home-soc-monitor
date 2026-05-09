package com.security.home.detection;

import com.security.home.entity.*;
import com.security.home.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class DetectionEngine {

    private final Set<String> knownDevices = new HashSet<>();

    private final RulesEngine rulesEngine;
    private final SecurityEventRepository repository;

    public DetectionEngine(RulesEngine rulesEngine,
                           SecurityEventRepository repository) {
        this.rulesEngine = rulesEngine;
        this.repository = repository;
    }

    // =========================
    // NORMAL TRAFFIC PIPELINE
    // =========================
    public List<SecurityEvent> process(Device device) {

        List<SecurityEvent> results = new ArrayList<>();

        String mac = normalize(device.getMac());

        // NEW DEVICE DETECTION
        if (knownDevices.add(mac)) {

            SecurityEvent event = new SecurityEvent(
                    SecurityEventType.NEW_DEVICE,
                    EventSeverity.MEDIUM,
                    "New device joined network: " + device.getVendor(),
                    device.getIp()
            );

            results.add(repository.save(event));
        }

        // RULES ENGINE ANALYSIS
        List<SecurityEvent> ruleEvents = rulesEngine.analyze(device);

        for (SecurityEvent event : ruleEvents) {
            results.add(repository.save(event));
        }

        return results;
    }

    // =========================
    // ATTACK PIPELINE
    // =========================
    public List<SecurityEvent> processAttack(Device device) {

        List<SecurityEvent> results = new ArrayList<>();

        String mac = normalize(device.getMac());

        for (int i = 0; i < 5; i++) {

            SecurityEvent event = new SecurityEvent(
                    SecurityEventType.PORT_SCAN,
                    EventSeverity.HIGH,
                    "Port scanning detected from device: " + device.getVendor(),
                    device.getIp()
            );

            results.add(repository.save(event));
        }

        return results;
    }

    // =========================
    // UTILS
    // =========================
    private String normalize(String mac) {
        return mac == null ? "UNKNOWN" : mac.toUpperCase(Locale.ROOT).trim();
    }
}