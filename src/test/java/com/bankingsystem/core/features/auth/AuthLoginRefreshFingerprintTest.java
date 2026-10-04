package com.bankingsystem.core.features.auth;

import com.bankingsystem.core.features.accesscontrol.domain.Role;
import com.bankingsystem.core.features.accesscontrol.domain.repository.RoleRepository;
import com.bankingsystem.core.features.auth.application.AuthService;
import com.bankingsystem.core.features.auth.application.LoginAuthenticationService;
import com.bankingsystem.core.features.auth.application.PasswordResetService;
import com.bankingsystem.core.features.auth.application.impl.AuthServiceImpl;
import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.User;
import com.bankingsystem.core.features.auth.domain.repository.PasswordResetTokenRepository;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import com.bankingsystem.core.features.auth.domain.repository.UserRepository;
import com.bankingsystem.core.features.auth.domain.repository.VerificationTokenRepository;
import com.bankingsystem.core.features.auth.interfaces.AuthController;
import com.bankingsystem.core.features.auth.interfaces.dto.JwtResponse;
import com.bankingsystem.core.features.auth.interfaces.dto.LoginRequest;
import com.bankingsystem.core.features.system.application.EmailService;
import com.bankingsystem.core.modules.common.config.AppProperties;
import com.bankingsystem.core.modules.common.config.JwtProperties;
import com.bankingsystem.core.modules.common.security.JwtUtils;
import com.bankingsystem.core.modules.common.security.SessionTokenFingerprint;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthLoginRefreshFingerprintTest {

    private static final String SECRET = "test-jwt-secret-012345678901234567890123";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-04T10:15:30Z"), ZoneOffset.UTC);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void loginReturnsScopedBearerAndPersistsOnlyItsFingerprint() {
        UserRepository users = mock(UserRepository.class);
        SessionRepository sessions = mock(SessionRepository.class);
        User user = user("alice");
        when(users.findByUsername("alice")).thenReturn(Optional.of(user));
        LoginAuthenticationService login = mock(LoginAuthenticationService.class);
        when(login.authenticate("alice", "Password1!", "10.0.0.1"))
                .thenReturn(new LoginAuthenticationService.LoginResult(
                        new UsernamePasswordAuthenticationToken("alice", null), user));
        JwtUtils jwtUtils = jwtUtils();
        AuthController controller = controller(login, jwtUtils, authService(users, sessions), users);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("alice");
        loginRequest.setPassword("Password1!");

        ResponseEntity<?> response = controller.authenticateUser(loginRequest, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JwtResponse body = (JwtResponse) response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getUsername()).isEqualTo("alice");
        assertThat(body.getRole()).isEqualTo("CUSTOMER");
        var claims = jwtUtils.parseAndValidate(body.getToken());
        assertThat(claims.getIssuer()).isEqualTo("bank-core");
        assertThat(claims.getAudience()).isEqualTo("bank-core-api");
        assertThat(new ObjectMapper().convertValue(body, new TypeReference<Map<String, Object>>() { }).keySet())
                .containsExactlyInAnyOrder("token", "username", "role");

        ArgumentCaptor<Session> captor = ArgumentCaptor.forClass(Session.class);
        verify(sessions).save(captor.capture());
        assertThat(captor.getValue().getTokenFingerprint()).isEqualTo(SessionTokenFingerprint.from(body.getToken()));
        assertThat(captor.getValue().getTokenFingerprint()).isNotEqualTo(body.getToken());
    }

    @Test
    void refreshReplacesScopedSessionWithNewJtiAndFingerprint() {
        UserRepository users = mock(UserRepository.class);
        SessionRepository sessions = mock(SessionRepository.class);
        User user = user("alice");
        when(users.findByUsername("alice")).thenReturn(Optional.of(user));
        JwtUtils jwtUtils = jwtUtils();
        String oldToken = jwtUtils.generateJwtToken("alice", "CUSTOMER");
        String oldFingerprint = SessionTokenFingerprint.from(oldToken);
        Session oldSession = new Session();
        oldSession.setUser(user);
        oldSession.setTokenFingerprint(oldFingerprint);
        oldSession.setIsActive(true);
        oldSession.setExpiryTime(LocalDateTime.now(CLOCK).plusHours(2));
        when(sessions.findByTokenFingerprint(oldFingerprint)).thenReturn(Optional.of(oldSession));
        AuthController controller = controller(mock(LoginAuthenticationService.class), jwtUtils, authService(users, sessions), users);
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("10.0.0.2");

        ResponseEntity<?> response = controller.refreshToken(
                Map.of("username", "alice"), "Bearer " + oldToken, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String replacement = (String) ((Map<?, ?>) response.getBody()).get("token");
        var oldClaims = jwtUtils.parseAndValidate(oldToken);
        var newClaims = jwtUtils.parseAndValidate(replacement);
        assertThat(newClaims.getIssuer()).isEqualTo("bank-core");
        assertThat(newClaims.getAudience()).isEqualTo("bank-core-api");
        assertThat(newClaims.getId()).isNotEqualTo(oldClaims.getId());
        assertThat(oldSession.getIsActive()).isFalse();
        verify(sessions, times(2)).findByTokenFingerprint(oldFingerprint);
        verify(sessions, never()).findByTokenFingerprint(oldToken);

        ArgumentCaptor<Session> saved = ArgumentCaptor.forClass(Session.class);
        verify(sessions, times(2)).save(saved.capture());
        Session replacementSession = saved.getAllValues().get(1);
        assertThat(replacementSession.getTokenFingerprint()).isEqualTo(SessionTokenFingerprint.from(replacement));
        assertThat(replacementSession.getTokenFingerprint()).isNotEqualTo(replacement);
    }

    @Test
    void legacyTokenCannotRefreshOrReachSessionLookup() {
        UserRepository users = mock(UserRepository.class);
        SessionRepository sessions = mock(SessionRepository.class);
        JwtUtils jwtUtils = jwtUtils();
        String legacyToken = io.jsonwebtoken.Jwts.builder()
                .setId("legacy-jti")
                .setSubject("alice")
                .claim("role", "CUSTOMER")
                .setIssuedAt(java.util.Date.from(CLOCK.instant()))
                .setExpiration(java.util.Date.from(CLOCK.instant().plusSeconds(300)))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                        io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();
        AuthController controller = controller(
                mock(LoginAuthenticationService.class), jwtUtils, authService(users, sessions), users);

        ResponseEntity<?> response = controller.refreshToken(
                Map.of("username", "alice"), "Bearer " + legacyToken, mock(HttpServletRequest.class));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(sessions, users);
    }

    @Test
    void validateTokenResponseKeepsUsernameAndRoleOnly() {
        JwtUtils jwtUtils = jwtUtils();
        AuthController controller = controller(
                mock(LoginAuthenticationService.class), jwtUtils, mock(AuthService.class), mock(UserRepository.class));
        String token = jwtUtils.generateJwtToken("alice", "CUSTOMER");

        ResponseEntity<?> response = controller.validateToken("Bearer " + token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(Map.of("username", "alice", "role", "CUSTOMER"));
    }

    @Test
    void invalidIssuerOnValidateTokenRemainsUnauthorized() {
        JwtUtils jwtUtils = jwtUtils();
        AuthController controller = controller(
                mock(LoginAuthenticationService.class), jwtUtils, mock(AuthService.class), mock(UserRepository.class));
        String token = io.jsonwebtoken.Jwts.builder()
                .setId("wrong-issuer-jti")
                .setIssuer("another-core")
                .setSubject("alice")
                .setAudience("bank-core-api")
                .claim("role", "CUSTOMER")
                .setIssuedAt(java.util.Date.from(CLOCK.instant()))
                .setExpiration(java.util.Date.from(CLOCK.instant().plusSeconds(300)))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                        io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();

        ResponseEntity<?> response = controller.validateToken("Bearer " + token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private static AuthController controller(
            LoginAuthenticationService login, JwtUtils jwtUtils, AuthService authService, UserRepository users) {
        return new AuthController(
                login,
                jwtUtils,
                authService,
                users,
                mock(PasswordResetService.class),
                mock(PasswordResetTokenRepository.class));
    }

    private static AuthServiceImpl authService(UserRepository users, SessionRepository sessions) {
        return new AuthServiceImpl(
                users,
                mock(RoleRepository.class),
                mock(PasswordEncoder.class),
                sessions,
                mock(VerificationTokenRepository.class),
                mock(EmailService.class),
                new AppProperties(),
                CLOCK);
    }

    private static JwtUtils jwtUtils() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setExpirationMs(60_000);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        return new JwtUtils(properties, CLOCK);
    }

    private static User user(String username) {
        Role role = new Role();
        role.setRoleName("CUSTOMER");
        User user = new User();
        user.setUsername(username);
        user.setRole(role);
        return user;
    }
}
