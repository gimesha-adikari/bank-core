package com.bankingsystem.core.modules.common.security;

import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.Optional;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsServiceImpl userDetailsService;
    private final SessionRepository sessionRepository;
    private final Clock clock;

    public JwtAuthFilter(JwtUtils jwtUtils,
                         UserDetailsServiceImpl userDetailsService,
                         SessionRepository sessionRepository) {
        this(jwtUtils, userDetailsService, sessionRepository, Clock.systemUTC());
    }

    @Autowired
    public JwtAuthFilter(JwtUtils jwtUtils,
                         UserDetailsServiceImpl userDetailsService,
                         SessionRepository sessionRepository,
                         Clock clock) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
        this.sessionRepository = sessionRepository;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }
        SecurityContextHolder.clearContext();
        if ("Bearer".equals(authHeader) || authHeader.startsWith("Bearer ")) {
            String token = authHeader.length() > 7 ? authHeader.substring(7) : "";
            if (token.isBlank()) {
                reject(response);
                return;
            }
            if (!authenticate(token, request, response)) {
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean authenticate(String token,
                                 HttpServletRequest request,
                                 HttpServletResponse response) throws IOException {
        final Claims claims;
        try {
            claims = jwtUtils.parseAndValidate(token);
        } catch (JwtUtils.JwtValidationException e) {
            reject(response);
            return false;
        }

        final String username;
        final String role;
        try {
            username = claims.getSubject();
            Object roleValue = claims.get("role");
            role = roleValue instanceof String value ? value : null;
        } catch (RuntimeException e) {
            reject(response);
            return false;
        }
        if (username == null || username.isBlank() || role == null || role.isBlank()) {
            reject(response);
            return false;
        }

        String tokenFingerprint = SessionTokenFingerprint.from(token);
        Optional<Session> sessionOpt = sessionRepository.findByTokenFingerprint(tokenFingerprint);
        if (sessionOpt.isEmpty()) {
            reject(response);
            return false;
        }
        Session session = sessionOpt.get();
        if (!Boolean.TRUE.equals(session.getIsActive())) {
            reject(response);
            return false;
        }
        if (session.getExpiryTime() == null || !session.getExpiryTime().isAfter(LocalDateTime.now(clock))) {
            reject(response);
            return false;
        }

        final UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (RuntimeException e) {
            reject(response);
            return false;
        }
        if (!userDetails.isEnabled()) {
            reject(response);
            return false;
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        java.util.List.of(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase(Locale.ROOT))));
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return true;
    }

    private static void reject(HttpServletResponse response) throws IOException {
        SecurityContextHolder.clearContext();
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
