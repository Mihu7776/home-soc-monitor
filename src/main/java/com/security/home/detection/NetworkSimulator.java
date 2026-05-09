package com.security.home.detection;

import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

import java.util.List;
import java.util.Random;

public class NetworkSimulator {

    private final DetectionEngine engine;
    private final Random random = new Random();

    // 🔥 STAŁA “DOMOWA SIEĆ”
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

        for (int i = 0; i < 15; i++) {

            Device device = pickRandomDevice();

            List<SecurityEvent> events = engine.process(device);

            if (events.isEmpty()) {
                System.out.println("OK: " + device.getIp() + " (" + device.getVendor() + ")");
            } else {
                for (SecurityEvent e : events) {
                    System.out.println("🚨 " + e.getType() + " [" + e.getSeverity() + "]");
                    System.out.println("   " + e.getMessage());
                    System.out.println("   SRC: " + e.getSourceIp());
                }
            }

            sleep();
        }

        System.out.println("\n--- SWITCHING TO ATTACK SIMULATION ---\n");

        simulateAttack(devices.get(4));

        System.out.println("\n=== SIMULATION END ===\n");
    }

    private Device pickRandomDevice() {
        return devices.get(random.nextInt(devices.size()));
    }

    private void sleep() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException ignored) {
        }
    }

    private void simulateAttack(Device attacker) {

        System.out.println("\n⚠️ SIMULATING PORT SCAN FROM: " + attacker.getIp());

        for (int i = 0; i < 15; i++) {

            List<SecurityEvent> events = engine.processAttack(attacker);

            for (SecurityEvent e : events) {
                System.out.println("🚨 " + e.getType() + " [" + e.getSeverity() + "]");
                System.out.println("   " + e.getMessage());
                System.out.println("   SRC: " + e.getSourceIp());
            }

            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
            }
        }

        System.out.println("\n⚠️ ATTACK SIMULATION END\n");
    }
}