package com.bankingsystem.core.modules.common.security;

import com.bankingsystem.core.modules.common.config.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Clock;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final JwtProperties jwtProperties;
    private final Clock clock;

    public JwtUtils(JwtProperties jwtProperties) {
        this(jwtProperties, Clock.systemUTC());
    }

    @Autowired
    public JwtUtils(JwtProperties jwtProperties, Clock clock) {
        this.jwtProperties = jwtProperties;
        this.clock = clock;
        this.jwtProperties.validateForRuntime();
    }


    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateJwtToken(String username, String roleName) {
        return Jwts.builder()
                .setId(java.util.UUID.randomUUID().toString())
                .setIssuer(jwtProperties.getIssuer())
                .setSubject(username)
                .setAudience(jwtProperties.getAudience())
                .claim("role", roleName)
                .setIssuedAt(Date.from(clock.instant()))
                .setExpiration(new Date(clock.millis() + jwtProperties.getExpirationMs()))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return parseAndValidate(token).getSubject();
    }

    public String getRoleFromJwtToken(String token) {
        return parseAndValidate(token).get("role", String.class);
    }

    public boolean validateJwtToken(String authToken) {
        try {
            parseAndValidate(authToken);
            return true;
        } catch (JwtValidationException e) {
            return false;
        }
    }

    public Claims parseAndValidate(String token) {
        if (token == null || token.isBlank()) {
            logger.warn("AUTH_TOKEN_MALFORMED");
            throw new JwtValidationException("AUTH_TOKEN_MALFORMED");
        }
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .setClock(() -> Date.from(clock.instant()))
                    .requireIssuer(jwtProperties.getIssuer())
                    .requireAudience(jwtProperties.getAudience())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            Date expiration = claims.getExpiration();
            if (expiration == null || !expiration.after(Date.from(clock.instant()))) {
                logger.warn("AUTH_TOKEN_EXPIRED");
                throw new JwtValidationException("AUTH_TOKEN_EXPIRED");
            }
            return claims;
        } catch (ExpiredJwtException e) {
            logger.warn("AUTH_TOKEN_EXPIRED");
            throw new JwtValidationException("AUTH_TOKEN_EXPIRED");
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("AUTH_TOKEN_INVALID");
            throw new JwtValidationException("AUTH_TOKEN_INVALID");
        }
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public static final class JwtValidationException extends RuntimeException {
        public JwtValidationException(String category) {
            super(category);
        }
    }
}
