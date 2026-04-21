package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

import java.util.List;
import java.util.Random;

public class NetworkSimulator {

    private final DetectionEngine engine;
    private final Random random = new Random();

    // 🔥 STAŁA “DOMOWA SIEĆ” (realistyczne urządzenia)
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

        System.out.println("\n=== NETWORK TRAFFIC SIMULATION START ===\n");

        // 🔥 symulujemy 15 zdarzeń (ruch w czasie)
        for (int i = 0; i < 15; i++) {

            Device device = pickRandomDevice();

            SecurityEvent event = engine.process(device);

            if (event != null) {
                System.out.println("🚨 EVENT: " + event.getType());
                System.out.println("   " + event.getMessage());
                System.out.println("   SRC: " + event.getSourceIp());
            } else {
                System.out.println("OK: " + device.getIp() + " (" + device.getVendor() + ")");
            }

            sleep();
        }

        System.out.println("\n=== SIMULATION END ===\n");
    }

    private Device pickRandomDevice() {
        return devices.get(random.nextInt(devices.size()));
    }

    private void sleep() {
        try {
            Thread.sleep(300); // symulacja “czasu sieci”
        } catch (InterruptedException ignored) {
        }
    }
}