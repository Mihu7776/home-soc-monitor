package com.security.home.entity;

public class Device {

    private String ip;
    private String mac;
    private String vendor;

    public Device(String ip, String mac, String vendor) {
        this.ip = ip;
        this.mac = mac;
        this.vendor = vendor;
    }

    public String getIp() {
        return ip;
    }

    public String getMac() {
        return mac;
    }

    public String getVendor() {
        return vendor;
    }
}