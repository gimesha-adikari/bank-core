package com.bankingsystem.core.modules.common.security;

import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.User;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import com.bankingsystem.core.modules.common.config.JwtProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static io.jsonwebtoken.Jwts.claims;

class JwtAuthFilterTest {

    private static final String TOKEN = "test-token";

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void expiredActiveSessionIsRejectedAndClearsSecurityContext() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN)))
                .thenReturn(Optional.of(session(LocalDateTime.now(Clock.systemUTC()).minusSeconds(1))));
        when(users.loadUserByUsername("alice")).thenReturn(userDetails(true));
        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "stale", null, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ADMIN"))));

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void sessionAtExpiryBoundaryIsRejected() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        Clock clock = Clock.fixed(Instant.parse("2026-10-02T00:00:00Z"), ZoneOffset.UTC);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN)))
                .thenReturn(Optional.of(session(LocalDateTime.now(clock))));

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions, clock);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void inactiveSessionIsRejected() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        Session inactive = session(LocalDateTime.now(Clock.systemUTC()).plusMinutes(5));
        inactive.setIsActive(false);
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN))).thenReturn(Optional.of(inactive));

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void unknownSessionIsRejected() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN))).thenReturn(Optional.empty());

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void missingAuthorizationHeaderLeavesRequestUnauthenticatedForSecurityChain() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(mock(JwtUtils.class), mock(UserDetailsServiceImpl.class), mock(SessionRepository.class));
        AtomicBoolean continued = new AtomicBoolean();

        MockHttpServletResponse response = invoke(filter, null, continued);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(continued).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void expiredJwtIsRejectedBeforeSessionLookup() throws Exception {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setExpirationMs(-1);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        JwtUtils jwtUtils = new JwtUtils(properties);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + jwtUtils.generateJwtToken("alice", "CUSTOMER"), new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void activeNonExpiredSessionIsAccepted() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN)))
                .thenReturn(Optional.of(session(LocalDateTime.now(Clock.systemUTC()).plusMinutes(5))));
        when(users.loadUserByUsername("alice")).thenReturn(userDetails(true));
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, continued);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(continued).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void disabledPrincipalIsRejected() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        when(jwtUtils.parseAndValidate(TOKEN)).thenReturn(validClaims());
        when(sessions.findByTokenFingerprint(SessionTokenFingerprint.from(TOKEN)))
                .thenReturn(Optional.of(session(LocalDateTime.now(Clock.systemUTC()).plusMinutes(5))));
        when(users.loadUserByUsername("alice")).thenReturn(userDetails(false));
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + TOKEN, continued);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(continued).isFalse();
    }

    @Test
    void malformedJwtIsRejectedWithoutEscapingTheFilter() throws Exception {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setExpirationMs(60_000);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        JwtUtils jwtUtils = new JwtUtils(properties);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer not.a.jwt", continued);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(continued).isFalse();
    }

    @Test
    void badSignatureIsRejectedWithoutSessionLookup() throws Exception {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setExpirationMs(60_000);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        JwtUtils jwtUtils = new JwtUtils(properties);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        String token = jwtUtils.generateJwtToken("alice", "CUSTOMER");
        String[] segments = token.split("\\.");
        char first = segments[2].charAt(0);
        String invalidSignature = (first == 'A' ? 'B' : 'A') + segments[2].substring(1);
        String invalid = segments[0] + "." + segments[1] + "." + invalidSignature;

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + invalid, new AtomicBoolean());

        assertThat(response.getStatus()).isEqualTo(401);
        org.mockito.Mockito.verifyNoInteractions(sessions);
    }

    @Test
    void legacyTokenIsRejectedBeforeSessionOrUserLookup() throws Exception {
        assertRejectedBeforeStateAccess(signedToken(null, null));
    }

    @Test
    void wrongIssuerIsRejectedBeforeSessionOrUserLookup() throws Exception {
        assertRejectedBeforeStateAccess(signedToken("wrong-core", "bank-core-api"));
    }

    @Test
    void missingIssuerIsRejectedBeforeSessionOrUserLookup() throws Exception {
        assertRejectedBeforeStateAccess(signedToken(null, "bank-core-api"));
    }

    @Test
    void wrongAudienceIsRejectedBeforeSessionOrUserLookup() throws Exception {
        assertRejectedBeforeStateAccess(signedToken("bank-core", "another-api"));
    }

    @Test
    void missingAudienceIsRejectedBeforeSessionOrUserLookup() throws Exception {
        assertRejectedBeforeStateAccess(signedToken("bank-core", null));
    }

    @Test
    void validScopedTokenLooksUpFingerprintAndAuthenticates() throws Exception {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setExpirationMs(60_000);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        JwtUtils jwtUtils = new JwtUtils(properties);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        String token = signedToken("bank-core", "bank-core-api");
        String fingerprint = SessionTokenFingerprint.from(token);
        when(sessions.findByTokenFingerprint(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(Optional.of(session(LocalDateTime.now(Clock.systemUTC()).plusMinutes(5))));
        when(users.loadUserByUsername("alice")).thenReturn(userDetails(true));
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + token, continued);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(continued).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        org.mockito.Mockito.verify(sessions).findByTokenFingerprint(fingerprint);
    }

    @Test
    void emptyBearerIsRejected() throws Exception {
        JwtUtils jwtUtils = mock(JwtUtils.class);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer ", continued);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(continued).isFalse();
    }

    @Test
    void bareBearerIsRejected() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(mock(JwtUtils.class), mock(UserDetailsServiceImpl.class), mock(SessionRepository.class));
        AtomicBoolean continued = new AtomicBoolean();

        MockHttpServletResponse response = invoke(filter, "Bearer", continued);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(continued).isFalse();
    }

    @Test
    void wrongRoleRemainsForbidden() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "alice", null, List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_CUSTOMER"))));
        AuthorizationFilter authorizationFilter = new AuthorizationFilter((authentication, context) ->
                new AuthorizationDecision(authentication.get() != null && authentication.get().getAuthorities().stream()
                        .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))));
        ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter((request, response, exception) ->
                response.sendError(401));
        exceptionTranslationFilter.setAccessDeniedHandler((request, response, exception) -> response.sendError(403));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        exceptionTranslationFilter.doFilter(request, response,
                (req, res) -> authorizationFilter.doFilter(req, res,
                        (nextReq, nextRes) -> ((jakarta.servlet.http.HttpServletResponse) nextRes).setStatus(200)));

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void userDetailsReflectCurrentActiveState() {
        var repository = mock(com.bankingsystem.core.features.auth.domain.repository.UserRepository.class);
        var role = new com.bankingsystem.core.features.accesscontrol.domain.Role();
        role.setRoleName("CUSTOMER");
        User user = new User();
        user.setUsername("alice");
        user.setPasswordHash("hash");
        user.setRole(role);
        user.setIsActive(false);
        when(repository.findByUsername("alice")).thenReturn(Optional.of(user));

        UserDetails details = new UserDetailsServiceImpl(repository).loadUserByUsername("alice");

        assertThat(details.isEnabled()).isFalse();
    }

    private static Session session(LocalDateTime expiry) {
        Session session = new Session();
        session.setIsActive(true);
        session.setExpiryTime(expiry);
        return session;
    }

    private static void assertRejectedBeforeStateAccess(String token) throws Exception {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-jwt-secret-012345678901234567890123");
        properties.setExpirationMs(60_000);
        properties.setIssuer("bank-core");
        properties.setAudience("bank-core-api");
        JwtUtils jwtUtils = new JwtUtils(properties);
        UserDetailsServiceImpl users = mock(UserDetailsServiceImpl.class);
        SessionRepository sessions = mock(SessionRepository.class);
        AtomicBoolean continued = new AtomicBoolean();

        JwtAuthFilter filter = new JwtAuthFilter(jwtUtils, users, sessions);
        MockHttpServletResponse response = invoke(filter, "Bearer " + token, continued);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(continued).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        org.mockito.Mockito.verifyNoInteractions(sessions, users);
    }

    private static String signedToken(String issuer, String audience) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .setId("test-jti")
                .setSubject("alice")
                .claim("role", "CUSTOMER")
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(300)));
        if (issuer != null) {
            builder.setIssuer(issuer);
        }
        if (audience != null) {
            builder.setAudience(audience);
        }
        return builder.signWith(
                        Keys.hmacShaKeyFor("test-jwt-secret-012345678901234567890123".getBytes(StandardCharsets.UTF_8)),
                        SignatureAlgorithm.HS256)
                .compact();
    }


    private static io.jsonwebtoken.Claims validClaims() {
        io.jsonwebtoken.Claims claims = claims().setSubject("alice");
        claims.put("role", "CUSTOMER");
        return claims;
    }

    private static UserDetails userDetails(boolean enabled) {
        return org.springframework.security.core.userdetails.User.withUsername("alice")
                .password("hash")
                .authorities(List.of())
                .disabled(!enabled)
                .build();
    }

    private static MockHttpServletResponse invoke(JwtAuthFilter filter, String header, AtomicBoolean continued)
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/v1/protected");
        if (header != null) request.addHeader("Authorization", header);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> continued.set(true);
        filter.doFilterInternal(request, response, chain);
        return response;
    }
}
