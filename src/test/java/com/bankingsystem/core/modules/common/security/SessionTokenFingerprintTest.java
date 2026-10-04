package com.bankingsystem.core.modules.common.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SessionTokenFingerprintTest {

    @Test
    void fingerprintIsDeterministicForTheExactInput() {
        assertThat(SessionTokenFingerprint.from("header.payload.signature"))
                .isEqualTo(SessionTokenFingerprint.from("header.payload.signature"));
    }

    @Test
    void differentInputsProduceDifferentFingerprints() {
        assertThat(SessionTokenFingerprint.from("header.payload.signature"))
                .isNotEqualTo(SessionTokenFingerprint.from("header.payload.changed"));
    }

    @Test
    void fingerprintUsesSha256LowercaseHexOfExactUtf8Bytes() {
        String fingerprint = SessionTokenFingerprint.from("header.payload.signature");

        assertThat(fingerprint).isEqualTo("256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6");
        assertThat(fingerprint).hasSize(64).matches("^[0-9a-f]{64}$");
    }

    @Test
    void fingerprintDoesNotTrimInput() {
        assertThat(SessionTokenFingerprint.from("header.payload.signature "))
                .isNotEqualTo(SessionTokenFingerprint.from("header.payload.signature"));
    }

    @Test
    void nullAndBlankInputsAreRejected() {
        assertThatThrownBy(() -> SessionTokenFingerprint.from(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Token is required");
        assertThatThrownBy(() -> SessionTokenFingerprint.from("  "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Token is required");
    }
}
