package com.security.home.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private SecurityEventType type;

    @Enumerated(EnumType.STRING)
    private EventSeverity severity;

    private String message;
    private String sourceIp;

    private LocalDateTime timestamp;

    public SecurityEvent() {
        this.timestamp = LocalDateTime.now();
    }

    public SecurityEvent(SecurityEventType type,
                         EventSeverity severity,
                         String message,
                         String sourceIp) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.sourceIp = sourceIp;
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public SecurityEventType getType() {
        return type;
    }

    public EventSeverity getSeverity() {
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

    public void setId(Long id) {
        this.id = id;
    }

    public void setType(SecurityEventType type) {
        this.type = type;
    }

    public void setSeverity(EventSeverity severity) {
        this.severity = severity;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}