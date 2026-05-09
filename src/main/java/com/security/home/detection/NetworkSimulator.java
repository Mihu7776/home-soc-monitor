package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;

@Component
public class NetworkSimulator {

    private final DetectionEngine engine;
    private final Random random = new Random();

    private final List<Device> devices = List.of(
            new Device("192.168.0.10", "AA:BB:CC:01", "TP-Link Router"),
            new Device("192.168.0.11", "AA:BB:CC:02", "iPhone"),
            new Device("192.168.0.12", "AA:BB:CC:03", "Windows PC"),
            new Device("192.168.0.13", "AA:BB:CC:04", "Smart TV"),
            new Device("192.168.0.14", "AA:BB:CC:05", "IoT Camera")
    );

    public NetworkSimulator(DetectionEngine engine) {
        this.engine = engine;
    }

    public void simulateTraffic() {

        for (int i = 0; i < 15; i++) {

            Device device = pickRandomDevice();

            List<SecurityEvent> events = engine.process(device);

            handleEvents(events);

            sleep();
        }

        simulateAttack(devices.get(4));
    }

    private void handleEvents(List<SecurityEvent> events) {
        for (SecurityEvent e : events) {
            // później: logger
            System.out.println(e.getType() + " [" + e.getSeverity() + "]");
        }
    }

    private Device pickRandomDevice() {
        return devices.get(random.nextInt(devices.size()));
    }

    private void sleep() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException ignored) {}
    }

    private void simulateAttack(Device attacker) {

        for (int i = 0; i < 15; i++) {
            List<SecurityEvent> events = engine.processAttack(attacker);
            handleEvents(events);

            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {}
        }
    }
}