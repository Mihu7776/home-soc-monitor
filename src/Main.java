package com.security.home;

import com.security.home.detection.DetectionEngine;
import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;

public class Main {

    public static void main(String[] args) {

        DetectionEngine engine = new DetectionEngine();

        Device d1 = new Device("192.168.0.10", "AA:BB:CC", "TP-Link");

        SecurityEvent event = engine.process(d1);

        if (event != null) {
            System.out.println("EVENT: " + event.getType());
            System.out.println("DESC: " + event.getMessage());
        }
    }
}