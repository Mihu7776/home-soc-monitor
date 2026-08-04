package com.security.home.detection.dns;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DnsQueryParserTest {

    private final DnsQueryParser parser = new DnsQueryParser();

    @Test
    void normalizesWhitespaceCaseAndTrailingDot() {
        ParsedDnsQuery query = parser.parse("  Camera-Feed.WebHook.Site. ").orElseThrow();

        assertThat(query.normalizedQuery()).isEqualTo("camera-feed.webhook.site");
        assertThat(query.baseDomain()).isEqualTo("webhook.site");
    }

    @Test
    void rejectsMalformedQueries() {
        assertThat(parser.parse("camera..webhook.site")).isEmpty();
        assertThat(parser.parse("-camera.example")).isEmpty();
        assertThat(parser.parse("camera_example.com")).isEmpty();
    }
}
