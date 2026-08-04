package com.security.home.detection.dns;

import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

/**
 * Converts raw DNS query values into a canonical form for detection rules.
 */
@Component
public class DnsQueryParser {

    public Optional<ParsedDnsQuery> parse(String rawQuery) {
        if (rawQuery == null) {
            return Optional.empty();
        }

        String normalized = rawQuery.trim().toLowerCase(Locale.ROOT);

        while (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        if (normalized.isBlank() || normalized.contains("..") || !isValidDomain(normalized)) {
            return Optional.empty();
        }

        return Optional.of(new ParsedDnsQuery(normalized, baseDomain(normalized)));
    }

    private boolean isValidDomain(String query) {
        if (query.length() > 253) {
            return false;
        }

        for (String label : query.split("\\.")) {
            if (label.isBlank() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                return false;
            }

            for (int index = 0; index < label.length(); index++) {
                char character = label.charAt(index);
                if (!(Character.isLetterOrDigit(character) || character == '-')) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Returns the final two labels for rule grouping. This deliberately avoids
     * claiming Public Suffix List accuracy, which would require a dedicated data source.
     */
    private String baseDomain(String normalizedQuery) {
        String[] labels = normalizedQuery.split("\\.");

        if (labels.length < 2) {
            return normalizedQuery;
        }

        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }
}
