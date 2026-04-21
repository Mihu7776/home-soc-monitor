package com.security.home.entity;

import java.time.LocalDateTime;

public class SecurityEvent {

    private String type;       // NEW_DEVICE, UNKNOWN_DEVICE
    private String severity;   // LOW, MEDIUM, HIGH
    private String message;
    private String sourceIp;
    private LocalDateTime timestamp;

    public SecurityEvent(String type, String severity, String message, String sourceIp) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.sourceIp = sourceIp;
        this.timestamp = LocalDateTime.now();
    }

    public String getType() {
        return type;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMessage() {
        return message;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}