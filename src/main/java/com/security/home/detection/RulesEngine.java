package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

import java.util.*;

public class RulesEngine {

    // 🔥 tracking requestów w czasie
    private final Map<String, List<Long>> requestTimeline = new HashMap<>();

    public List<SecurityEvent> analyze(Device device) {

        List<SecurityEvent> alerts = new ArrayList<>();

        String mac = device.getMac();
        long now = System.currentTimeMillis();

        // 📊 zapis requestu w czasie
        requestTimeline.putIfAbsent(mac, new ArrayList<>());
        List<Long> timestamps = requestTimeline.get(mac);

        timestamps.add(now);

        // 🔥 czyścimy stare wpisy (> 2 sekundy)
        timestamps.removeIf(t -> now - t > 2000);

        // 🚨 RULE: PORT SCAN
        if (timestamps.size() > 8) {
            alerts.add(new SecurityEvent(
                    "PORT_SCAN",
                    "HIGH",
                    "Possible port scanning detected from device: " + device.getVendor(),
                    device.getIp()
            ));
        }

        return alerts;
    }
}