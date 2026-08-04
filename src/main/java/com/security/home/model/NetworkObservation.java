package com.security.home.model;

import com.security.home.entity.Device;

public record NetworkObservation(
        String sourceIp,
        String sourceMac,
        String vendor,
        String destinationIp,
        Integer destinationPort,
        String protocol,
        Long bytesOut,
        String dnsQuery
) {
    public static NetworkObservation fromDevice(Device device) {
        return new NetworkObservation(
                device.getIp(),
                device.getMac(),
                device.getVendor(),
                null,
                null,
                null,
                0L,
                null
        );
    }
}
