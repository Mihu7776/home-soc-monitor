package com.security.home.repository;

import com.security.home.entity.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {
    List<SecurityEvent> findTop100ByOrderByTimestampDesc();
}