package com.bankingsystem.core.modules.common.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtPropertiesTest {

    @Test
    void missingSecretIsRejected() {
        JwtProperties properties = validProperties();
        properties.setSecret(null);

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT signing configuration is missing");
    }

    @Test
    void blankSecretIsRejected() {
        JwtProperties properties = validProperties();
        properties.setSecret("   ");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT signing configuration is missing");
    }

    @Test
    void placeholderAndShortSecretsAreRejected() {
        JwtProperties placeholder = validProperties();
        placeholder.setSecret("CHANGE_ME_TO_A_RANDOM_SECRET");
        JwtProperties shortSecret = validProperties();
        shortSecret.setSecret("short");

        assertThatThrownBy(placeholder::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("forbidden placeholder");
        assertThatThrownBy(shortSecret::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 UTF-8 bytes");
    }

    @Test
    void validSecretAndIdentifiersAreAccepted() {
        validProperties().validateForRuntime();
    }

    @Test
    void missingIssuerIsRejected() {
        JwtProperties properties = validProperties();
        properties.setIssuer(null);

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT issuer configuration is missing");
    }

    @Test
    void blankIssuerIsRejected() {
        JwtProperties properties = validProperties();
        properties.setIssuer("   ");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT issuer configuration is missing");
    }

    @Test
    void issuerWithLeadingWhitespaceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setIssuer(" bank-core");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT issuer configuration has surrounding whitespace");
    }

    @Test
    void issuerWithTrailingWhitespaceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setIssuer("bank-core ");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT issuer configuration has surrounding whitespace");
    }

    @Test
    void issuerWithControlCharacterIsRejected() {
        JwtProperties properties = validProperties();
        properties.setIssuer("bank-core\n");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT issuer configuration contains control characters");
    }

    @Test
    void missingAudienceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setAudience(null);

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT audience configuration is missing");
    }

    @Test
    void blankAudienceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setAudience("   ");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT audience configuration is missing");
    }

    @Test
    void audienceWithLeadingWhitespaceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setAudience(" bank-core-api");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT audience configuration has surrounding whitespace");
    }

    @Test
    void audienceWithTrailingWhitespaceIsRejected() {
        JwtProperties properties = validProperties();
        properties.setAudience("bank-core-api ");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT audience configuration has surrounding whitespace");
    }

    @Test
    void audienceWithControlCharacterIsRejected() {
        JwtProperties properties = validProperties();
        properties.setAudience("bank-core-api\u007f");

        assertThatThrownBy(properties::validateForRuntime)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT audience configuration contains control characters");
    }

    private static JwtProperties validProperties() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        return properties;
    }
}
