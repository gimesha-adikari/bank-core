package com.bankingsystem.core.features.auth;

import com.bankingsystem.core.features.accesscontrol.domain.repository.RoleRepository;
import com.bankingsystem.core.features.auth.application.impl.AuthServiceImpl;
import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.User;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import com.bankingsystem.core.features.auth.domain.repository.UserRepository;
import com.bankingsystem.core.features.auth.domain.repository.VerificationTokenRepository;
import com.bankingsystem.core.features.system.application.EmailService;
import com.bankingsystem.core.modules.common.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthServiceSessionFingerprintTest {

    private static final String TOKEN = "header.payload.signature";
    private static final String FINGERPRINT = "256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-04T10:15:30Z"), ZoneOffset.UTC);

    @Test
    void createSessionStoresFingerprintInsteadOfBearerToken() {
        UserRepository users = mock(UserRepository.class);
        SessionRepository sessions = mock(SessionRepository.class);
        User user = new User();
        user.setUsername("alice");
        when(users.findByUsername("alice")).thenReturn(Optional.of(user));
        AuthServiceImpl service = service(users, sessions, CLOCK);

        service.createSession(TOKEN, "alice", "127.0.0.1");

        ArgumentCaptor<Session> captor = ArgumentCaptor.forClass(Session.class);
        verify(sessions).save(captor.capture());
        assertThat(captor.getValue().getTokenFingerprint()).isEqualTo(FINGERPRINT);
        assertThat(captor.getValue().getTokenFingerprint()).isNotEqualTo(TOKEN);
        assertThat(captor.getValue().getLoginTime()).isEqualTo(LocalDateTime.now(CLOCK));
        assertThat(captor.getValue().getExpiryTime()).isEqualTo(LocalDateTime.now(CLOCK).plusHours(2));
    }

    @Test
    void sessionValidationLooksUpTheFingerprint() {
        SessionRepository sessions = mock(SessionRepository.class);
        when(sessions.findByTokenFingerprint(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(Optional.of(activeSession()));
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThat(service.isSessionValid(TOKEN)).isTrue();
        verify(sessions).findByTokenFingerprint(FINGERPRINT);
    }

    @Test
    void logoutLooksUpTheFingerprintAndDeactivatesTheSession() {
        SessionRepository sessions = mock(SessionRepository.class);
        Session session = activeSession();
        when(sessions.findByTokenFingerprint(org.mockito.ArgumentMatchers.anyString())).thenReturn(Optional.of(session));
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        service.logout(TOKEN);

        verify(sessions).findByTokenFingerprint(FINGERPRINT);
        assertThat(session.getIsActive()).isFalse();
        assertThat(session.getLogoutTime()).isNotNull();
        verify(sessions).save(session);
    }

    @Test
    void blankSessionValidationReturnsFalseWithoutRepositoryLookup() {
        SessionRepository sessions = mock(SessionRepository.class);
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThat(service.isSessionValid(null)).isFalse();
        assertThat(service.isSessionValid(" ")).isFalse();
        verifyNoInteractions(sessions);
    }

    @Test
    void inactiveSessionIsRejected() {
        SessionRepository sessions = mock(SessionRepository.class);
        Session session = activeSession();
        session.setIsActive(false);
        when(sessions.findByTokenFingerprint(FINGERPRINT)).thenReturn(Optional.of(session));
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThat(service.isSessionValid(TOKEN)).isFalse();
    }

    @Test
    void sessionAtExpiryBoundaryIsRejected() {
        Clock clock = Clock.fixed(Instant.parse("2026-10-04T10:15:30Z"), ZoneOffset.UTC);
        SessionRepository sessions = mock(SessionRepository.class);
        Session session = new Session();
        session.setIsActive(true);
        session.setExpiryTime(LocalDateTime.ofInstant(clock.instant(), ZoneOffset.UTC));
        when(sessions.findByTokenFingerprint(FINGERPRINT)).thenReturn(Optional.of(session));
        AuthServiceImpl service = service(mock(UserRepository.class), sessions, clock);

        assertThat(service.isSessionValid(TOKEN)).isFalse();
    }

    @Test
    void missingFingerprintSessionIsRejectedWithoutRawTokenLookup() {
        SessionRepository sessions = mock(SessionRepository.class);
        when(sessions.findByTokenFingerprint(FINGERPRINT)).thenReturn(Optional.empty());
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThat(service.isSessionValid(TOKEN)).isFalse();
        verify(sessions).findByTokenFingerprint(FINGERPRINT);
        verify(sessions, never()).findByTokenFingerprint(TOKEN);
    }

    @Test
    void logoutWithBlankTokenRetainsInvalidSessionFailure() {
        SessionRepository sessions = mock(SessionRepository.class);
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThatThrownBy(() -> service.logout(" "))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid session or already logged out.");
        verifyNoInteractions(sessions);
    }

    @Test
    void logoutWithInactiveSessionRetainsAlreadyLoggedOutFailure() {
        SessionRepository sessions = mock(SessionRepository.class);
        Session session = activeSession();
        session.setIsActive(false);
        when(sessions.findByTokenFingerprint(FINGERPRINT)).thenReturn(Optional.of(session));
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThatThrownBy(() -> service.logout(TOKEN))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Session already logged out.");
    }

    @Test
    void logoutWithMissingSessionRetainsInvalidSessionFailure() {
        SessionRepository sessions = mock(SessionRepository.class);
        AuthServiceImpl service = service(mock(UserRepository.class), sessions);

        assertThatThrownBy(() -> service.logout(TOKEN))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Invalid session or already logged out.");
        verify(sessions).findByTokenFingerprint(FINGERPRINT);
    }

    private static AuthServiceImpl service(UserRepository users, SessionRepository sessions) {
        return service(users, sessions, Clock.systemUTC());
    }

    private static AuthServiceImpl service(UserRepository users, SessionRepository sessions, Clock clock) {
        return new AuthServiceImpl(
                users,
                mock(RoleRepository.class),
                mock(PasswordEncoder.class),
                sessions,
                mock(VerificationTokenRepository.class),
                mock(EmailService.class),
                new AppProperties(),
                clock);
    }

    private static Session activeSession() {
        Session session = new Session();
        session.setIsActive(true);
        session.setExpiryTime(LocalDateTime.now().plusMinutes(5));
        return session;
    }
}
