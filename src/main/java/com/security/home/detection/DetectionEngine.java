package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

import java.util.*;

public class DetectionEngine {

    // 🔥 stan systemu (jak w realnym IDS/SOC sensorze)
    private final Set<String> knownDevices = new HashSet<>();
    private final List<SecurityEvent> events = new ArrayList<>();

    private final RulesEngine rulesEngine = new RulesEngine();

    // =========================
    // NORMAL TRAFFIC PIPELINE
    // =========================
    public List<SecurityEvent> process(Device device) {

        List<SecurityEvent> results = new ArrayList<>();

        String mac = normalize(device.getMac());

        System.out.println("[ENGINE] Processing device: " + mac);

        // 🔥 NEW DEVICE DETECTION
        if (knownDevices.add(mac)) {

            SecurityEvent event = new SecurityEvent(
                    "NEW_DEVICE",
                    "MEDIUM",
                    "Unknown device joined network: " + device.getVendor(),
                    device.getIp()
            );

            results.add(event);

            System.out.println("[ENGINE] NEW DEVICE DETECTED: " + mac);

        } else {
            System.out.println("[ENGINE] Known device: " + mac);
        }

        // 🔥 RULE ENGINE (normal behavioral detection)
        results.addAll(rulesEngine.analyze(device));

        // 🔥 zapis historii (SIEM-like log store)
        events.addAll(results);

        return results;
    }

    // =========================
    // ATTACK PIPELINE (SEPARATE SEMANTICS)
    // =========================
    public List<SecurityEvent> processAttack(Device device) {

        List<SecurityEvent> results = new ArrayList<>();

        String mac = normalize(device.getMac());

        System.out.println("[ENGINE] ATTACK MODE ACTIVE: " + mac);

        // 🔥 symulacja zachowania atakującego (nie 1 event, tylko pattern)
        for (int i = 0; i < 5; i++) {

            SecurityEvent event = new SecurityEvent(
                    "PORT_SCAN",
                    "HIGH",
                    "Repeated port scanning behavior detected from device: " + device.getVendor(),
                    device.getIp()
            );

            results.add(event);
            events.add(event);
        }

        return results;
    }

    // =========================
    // HISTORIAN (SIEM-style storage)
    // =========================
    public List<SecurityEvent> getEvents() {
        return Collections.unmodifiableList(events);
    }

    // =========================
    // UTILS
    // =========================
    private String normalize(String mac) {
        return mac == null ? "UNKNOWN" : mac.toUpperCase(Locale.ROOT).trim();
    }
}