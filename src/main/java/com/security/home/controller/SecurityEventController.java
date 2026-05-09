package com.security.home.controller;

import com.security.home.detection.DetectionEngine;
import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import com.security.home.repository.SecurityEventRepository;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class SecurityEventController {

    private final SecurityEventRepository repository;
    private final DetectionEngine engine;

    public SecurityEventController(SecurityEventRepository repository,
                                   DetectionEngine engine) {
        this.repository = repository;
        this.engine = engine;
    }

    // =========================
    // GET LAST EVENTS
    // =========================
    @GetMapping("/events")
    public List<SecurityEvent> getEvents() {
        return repository.findTop100ByOrderByTimestampDesc();
    }

    // =========================
    // SIMULATE SMART TV EXFIL ATTACK
    // =========================
    @PostMapping("/simulate/smart-tv/exfil")
    public List<SecurityEvent> simulateSmartTvExfil() {

        Device smartTv = new Device(
                "192.168.0.13",
                "AA:BB:CC:04",
                "Smart TV"
        );

        return engine.processAttack(smartTv);
    }

    // =========================
    // OPTIONAL: SIMULATE NORMAL TRAFFIC
    // =========================
    @PostMapping("/simulate/traffic")
    public List<SecurityEvent> simulateTraffic(@RequestBody Device device) {
        return engine.process(device);
    }
}