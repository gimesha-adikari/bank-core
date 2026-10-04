package com.bankingsystem.core.features.auth;

import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import jakarta.persistence.Column;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class SessionFingerprintMappingTest {

    @Test
    void fingerprintPropertyKeepsTheExistingPhysicalColumnContract() throws Exception {
        Column column = Session.class.getDeclaredField("tokenFingerprint").getAnnotation(Column.class);

        assertThat(column.name()).isEqualTo("token");
        assertThat(column.nullable()).isFalse();
        assertThat(column.unique()).isTrue();
        assertThat(column.length()).isEqualTo(255);
    }

    @Test
    void repositoryExposesFingerprintLookupWithoutRawTokenLookup() {
        assertThat(Arrays.stream(SessionRepository.class.getDeclaredMethods())
                .map(Method::getName)
                .toList())
                .contains("findByTokenFingerprint")
                .doesNotContain("findByToken");
    }
}
