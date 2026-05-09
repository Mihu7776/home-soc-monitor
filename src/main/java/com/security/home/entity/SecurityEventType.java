package com.security.home.entity;

public enum SecurityEventType {
    NEW_DEVICE,
    PORT_SCAN,
    SUSPICIOUS_DNS,
    POSSIBLE_DATA_EXFILTRATION,
    ROUTER_LOGIN_ATTEMPT,
    SURICATA_ALERT
}