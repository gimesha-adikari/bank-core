package com.bankingsystem.core.modules.common.config;

import lombok.Getter;
import lombok.Setter;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    private static final int MIN_SECRET_BYTES = 32;
    private static final java.util.Set<String> FORBIDDEN_SECRETS = java.util.Set.of(
            "local-development-secret-change-me-before-sharing",
            "CHANGE_ME",
            "CHANGE_ME_TO_A_RANDOM_SECRET"
    );

    private String secret;
    private long expirationMs;
    private String issuer;
    private String audience;

    @PostConstruct
    void validateConfiguration() {
        validateForRuntime();
    }

    public void validateForRuntime() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT signing configuration is missing");
        }
        if (FORBIDDEN_SECRETS.contains(secret.trim())) {
            throw new IllegalStateException("JWT signing configuration uses a forbidden placeholder");
        }
        if (secret.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("JWT signing configuration must be at least 32 UTF-8 bytes");
        }
        validateIdentifier(issuer, "issuer");
        validateIdentifier(audience, "audience");
    }

    private static void validateIdentifier(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("JWT " + name + " configuration is missing");
        }
        if (value.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new IllegalStateException("JWT " + name + " configuration contains control characters");
        }
        if (!value.equals(value.trim())) {
            throw new IllegalStateException("JWT " + name + " configuration has surrounding whitespace");
        }
    }
}
