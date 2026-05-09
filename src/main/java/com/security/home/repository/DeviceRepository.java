package com.security.home.repository;

import com.security.home.entity.Device;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DeviceRepository extends JpaRepository<Device, Long> {
    Optional<Device> findByMacIgnoreCase(String mac);
}