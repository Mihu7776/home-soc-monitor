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

    @Column(length = 512)
    private String message;

    private String sourceIp;
    private String sourceMac;
    private String destinationIp;
    private Integer destinationPort;
    private String protocol;
    private Long bytesOut;
    private Integer riskScore;
    private String mitreTactic;
    private String mitreTechnique;

    @Column(length = 1024)
    private String evidence;

    private LocalDateTime timestamp;

    public SecurityEvent() {
        this.timestamp = LocalDateTime.now();
    }

    public SecurityEvent(SecurityEventType type,
                         EventSeverity severity,
                         String message,
                         String sourceIp) {
        this(type, severity, message, sourceIp, null, null, null, null, null, null, null, null, null);
    }

    public SecurityEvent(SecurityEventType type,
                         EventSeverity severity,
                         String message,
                         String sourceIp,
                         String sourceMac,
                         String destinationIp,
                         Integer destinationPort,
                         String protocol,
                         Long bytesOut,
                         Integer riskScore,
                         String mitreTactic,
                         String mitreTechnique,
                         String evidence) {
        this.type = type;
        this.severity = severity;
        this.message = message;
        this.sourceIp = sourceIp;
        this.sourceMac = sourceMac;
        this.destinationIp = destinationIp;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.bytesOut = bytesOut;
        this.riskScore = riskScore;
        this.mitreTactic = mitreTactic;
        this.mitreTechnique = mitreTechnique;
        this.evidence = evidence;
        this.timestamp = LocalDateTime.now();
    }

    @PrePersist
    public void ensureTimestamp() {
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
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

    public String getSourceMac() {
        return sourceMac;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public Long getBytesOut() {
        return bytesOut;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public String getMitreTactic() {
        return mitreTactic;
    }

    public String getMitreTechnique() {
        return mitreTechnique;
    }

    public String getEvidence() {
        return evidence;
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

    public void setSourceMac(String sourceMac) {
        this.sourceMac = sourceMac;
    }

    public void setDestinationIp(String destinationIp) {
        this.destinationIp = destinationIp;
    }

    public void setDestinationPort(Integer destinationPort) {
        this.destinationPort = destinationPort;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setBytesOut(Long bytesOut) {
        this.bytesOut = bytesOut;
    }

    public void setRiskScore(Integer riskScore) {
        this.riskScore = riskScore;
    }

    public void setMitreTactic(String mitreTactic) {
        this.mitreTactic = mitreTactic;
    }

    public void setMitreTechnique(String mitreTechnique) {
        this.mitreTechnique = mitreTechnique;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
