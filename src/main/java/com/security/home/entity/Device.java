package com.security.home.entity;

import jakarta.persistence.*;

@Entity
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ip;
    private String mac;
    private String vendor;

    public Device() {
        // required by JPA
    }

    public Device(String ip, String mac, String vendor) {
        this.ip = ip;
        this.mac = mac;
        this.vendor = vendor;
    }

    public Long getId() {
        return id;
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

    public void setId(Long id) {
        this.id = id;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public void setVendor(String vendor) {
        this.vendor = vendor;
    }
}