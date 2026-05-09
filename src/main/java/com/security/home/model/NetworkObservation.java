package com.security.home.model;

public record NetworkObservation(
        String sourceIp,
        String sourceMac,
        String vendor,
        String destinationIp,
        Integer destinationPort,
        String protocol,
        Long bytesOut,
        String dnsQuery
) {}