package com.bankingsystem.core.modules.common.security;

import com.bankingsystem.core.modules.common.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtUtilsTest {

    private static final String SECRET = "test-jwt-secret-012345678901234567890123";
    private static final String ISSUER = "bank-core";
    private static final String AUDIENCE = "bank-core-api";
    private static final Instant NOW = Instant.parse("2026-10-04T10:15:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void generatedTokenContainsRequiredClaimsAndPreservesExistingClaims() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        String token = jwtUtils.generateJwtToken("alice", "CUSTOMER");
        var parsed = Jwts.parserBuilder()
                .setSigningKey(SECRET.getBytes(StandardCharsets.UTF_8))
                .setClock(() -> Date.from(CLOCK.instant()))
                .build()
                .parseClaimsJws(token);
        Claims claims = parsed.getBody();

        assertThat(claims.getId()).isNotBlank();
        assertThat(java.util.UUID.fromString(claims.getId())).isNotNull();
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo("HS256");
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getAudience()).isEqualTo(AUDIENCE);
        assertThat(claims.get("role", String.class)).isEqualTo("CUSTOMER");
        assertThat(claims.getIssuedAt()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpiration()).isEqualTo(Date.from(NOW.plusSeconds(60)));
    }

    @Test
    void unscopedLegacyTokenIsRejected() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken(null, null, false, 60));
    }

    @Test
    void wrongIssuerIsRejected() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken("wrong-core", AUDIENCE, false, 60));
    }

    @Test
    void missingIssuerIsRejected() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken(null, AUDIENCE, false, 60));
    }

    @Test
    void wrongAudienceIsRejected() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken(ISSUER, "another-api", false, 60));
    }

    @Test
    void missingAudienceIsRejected() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken(ISSUER, null, false, 60));
    }

    @Test
    void audienceArrayDoesNotSatisfyTheSingleStringContract() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertInvalid(jwtUtils, signedToken(ISSUER, AUDIENCE, true, 60));
    }

    @Test
    void expiredTokenRetainsExpiredCategory() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertThatThrownBy(() -> jwtUtils.parseAndValidate(signedToken(ISSUER, AUDIENCE, false, -1)))
                .isInstanceOf(JwtUtils.JwtValidationException.class)
                .hasMessage("AUTH_TOKEN_EXPIRED");
    }

    @Test
    void missingExpirationRetainsExpiredCategory() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);
        String token = Jwts.builder()
                .setId("missing-exp-jti")
                .setIssuer(ISSUER)
                .setSubject("alice")
                .setAudience(AUDIENCE)
                .claim("role", "CUSTOMER")
                .setIssuedAt(Date.from(NOW))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();

        assertThatThrownBy(() -> jwtUtils.parseAndValidate(token))
                .isInstanceOf(JwtUtils.JwtValidationException.class)
                .hasMessage("AUTH_TOKEN_EXPIRED");
    }

    @Test
    void blankTokenRemainsMalformed() {
        JwtUtils jwtUtils = new JwtUtils(properties(), CLOCK);

        assertThatThrownBy(() -> jwtUtils.parseAndValidate(" "))
                .isInstanceOf(JwtUtils.JwtValidationException.class)
                .hasMessage("AUTH_TOKEN_MALFORMED");
    }

    private static void assertInvalid(JwtUtils jwtUtils, String token) {
        assertThatThrownBy(() -> jwtUtils.parseAndValidate(token))
                .isInstanceOf(JwtUtils.JwtValidationException.class)
                .hasMessage("AUTH_TOKEN_INVALID");
    }

    private static JwtProperties properties() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setExpirationMs(60_000);
        properties.setIssuer(ISSUER);
        properties.setAudience(AUDIENCE);
        return properties;
    }

    private static String signedToken(String issuer, String audience, boolean audienceArray, long lifetimeSeconds) {
        var builder = Jwts.builder()
                .setId("test-jti")
                .setSubject("alice")
                .claim("role", "CUSTOMER")
                .setIssuedAt(Date.from(NOW))
                .setExpiration(Date.from(NOW.plusSeconds(lifetimeSeconds)));
        if (issuer != null) {
            builder.setIssuer(issuer);
        }
        if (audienceArray) {
            builder.claim("aud", List.of(audience));
        } else if (audience != null) {
            builder.setAudience(audience);
        }
        return builder.signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }
}
