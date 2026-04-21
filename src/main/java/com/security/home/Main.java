package com.security.home;

import com.security.home.detection.DetectionEngine;
import com.security.home.detection.NetworkSimulator;

public class Main {

    public static void main(String[] args) {

        DetectionEngine engine = new DetectionEngine();
        NetworkSimulator simulator = new NetworkSimulator(engine);

        simulator.simulateTraffic();
    }
}