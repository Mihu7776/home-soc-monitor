package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

import java.util.*;

public class DetectionEngine {

    // 🔥 stan systemu (jak w SIEM / SOC sensorze)
    private final Set<String> knownDevices = new HashSet<>();
    private final List<SecurityEvent> events = new ArrayList<>();

    public SecurityEvent process(Device device) {

        String mac = normalize(device.getMac());

        // 📊 log diagnostyczny (lekki, nie spamuje)
        System.out.println("[ENGINE] Processing device: " + mac);

        boolean isNewDevice = knownDevices.add(mac); // add() zwraca false jeśli już istnieje

        if (isNewDevice) {

            SecurityEvent event = new SecurityEvent(
                    "NEW_DEVICE",
                    "MEDIUM",
                    "Unknown device joined network: " + device.getVendor(),
                    device.getIp()
            );

            events.add(event);

            System.out.println("[ENGINE] NEW DEVICE DETECTED: " + mac);

            return event;
        }

        System.out.println("[ENGINE] Known device: " + mac);

        return null;
    }

    public List<SecurityEvent> getEvents() {
        return Collections.unmodifiableList(events);
    }

    // 🔥 normalizacja (ważne w realnych systemach)
    private String normalize(String mac) {
        return mac == null ? "UNKNOWN" : mac.toUpperCase(Locale.ROOT).trim();
    }
}