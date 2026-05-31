package com.security.home.controller;

import com.security.home.detection.DetectionEngine;
import com.security.home.entity.Device;
import com.security.home.entity.SecurityEvent;
import com.security.home.model.NetworkObservation;
import com.security.home.repository.DeviceRepository;
import com.security.home.repository.SecurityEventRepository;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api")
public class SecurityEventController {

    private final SecurityEventRepository repository;
    private final DeviceRepository deviceRepository;
    private final DetectionEngine engine;

    public SecurityEventController(SecurityEventRepository repository,
                                   DeviceRepository deviceRepository,
                                   DetectionEngine engine) {
        this.repository = repository;
        this.deviceRepository = deviceRepository;
        this.engine = engine;
    }

    @GetMapping("/devices")
    public List<Device> getDevices() {
        return deviceRepository.findAll();
    }

    @GetMapping("/events")
    public List<SecurityEvent> getEvents() {
        return repository.findTop100ByOrderByTimestampDesc();
    }

    @DeleteMapping("/events")
    public void clearEvents() {
        repository.deleteAll();
    }

    @PostMapping("/observe")
    public List<SecurityEvent> observe(@RequestBody NetworkObservation observation) {
        return engine.processObservation(observation);
    }

    @PostMapping("/simulate/smart-tv/exfil")
    public List<SecurityEvent> simulateSmartTvExfil() {
        Device smartTv = new Device(
                "192.168.0.13",
                "AA:BB:CC:04",
                "Smart TV"
        );

        return engine.processAttack(smartTv);
    }

    @PostMapping("/simulate/camera/exfil")
    public List<SecurityEvent> simulateCameraExfil() {
        Device camera = new Device(
                "192.168.0.14",
                "AA:BB:CC:05",
                "IoT Camera"
        );

        return engine.processAttack(camera);
    }

    @PostMapping("/simulate/traffic")
    public List<SecurityEvent> simulateTraffic(@RequestBody Device device) {
        return engine.process(device);
    }
}
