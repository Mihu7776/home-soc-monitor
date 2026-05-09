package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import com.security.home.entity.SecurityEventType;
import com.security.home.entity.EventSeverity;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class RulesEngine {

    private final Map<String, List<Long>> requestTimeline = new HashMap<>();

    public List<SecurityEvent> analyze(Device device) {

        List<SecurityEvent> alerts = new ArrayList<>();

        String mac = device.getMac();
        long now = System.currentTimeMillis();

        requestTimeline.putIfAbsent(mac, new ArrayList<>());
        List<Long> timestamps = requestTimeline.get(mac);

        timestamps.add(now);

        timestamps.removeIf(t -> now - t > 2000);

        if (timestamps.size() > 8) {
            alerts.add(new SecurityEvent(
                    SecurityEventType.PORT_SCAN,
                    EventSeverity.HIGH,
                    "Possible port scanning detected from device: " + device.getVendor(),
                    device.getIp()
            ));
        }

        return alerts;
    }
}