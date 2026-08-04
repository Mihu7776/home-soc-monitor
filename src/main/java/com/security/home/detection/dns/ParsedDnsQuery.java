package com.security.home.detection.dns;

/**
 * Normalized DNS query data used by detection rules.
 */
public record ParsedDnsQuery(String normalizedQuery, String baseDomain) {
}
