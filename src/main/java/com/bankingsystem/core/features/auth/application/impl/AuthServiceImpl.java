package com.bankingsystem.core.features.auth.application.impl;

import com.bankingsystem.core.modules.common.config.AppProperties;
import com.bankingsystem.core.modules.common.security.SessionTokenFingerprint;
import com.bankingsystem.core.features.auth.interfaces.dto.ChangePasswordRequest;
import com.bankingsystem.core.features.auth.interfaces.dto.RegisterRequest;
import com.bankingsystem.core.features.accesscontrol.domain.Role;
import com.bankingsystem.core.features.auth.domain.Session;
import com.bankingsystem.core.features.auth.domain.User;
import com.bankingsystem.core.features.auth.domain.VerificationToken;
import com.bankingsystem.core.features.accesscontrol.domain.repository.RoleRepository;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import com.bankingsystem.core.features.auth.domain.repository.UserRepository;
import com.bankingsystem.core.features.auth.domain.repository.VerificationTokenRepository;
import com.bankingsystem.core.features.auth.application.AuthService;
import com.bankingsystem.core.features.system.application.EmailService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionRepository sessionRepository;

    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;
    private final AppProperties appProperties;
    private final Clock clock;

    public AuthServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           SessionRepository sessionRepository,
                           VerificationTokenRepository tokenRepository,
                           EmailService emailService,
                           AppProperties appProperties) {
        this(userRepository, roleRepository, passwordEncoder, sessionRepository, tokenRepository,
                emailService, appProperties, Clock.systemUTC());
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AuthServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder,
                           SessionRepository sessionRepository,
                           VerificationTokenRepository tokenRepository,
                           EmailService emailService,
                           AppProperties appProperties,
                           Clock clock) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.sessionRepository = sessionRepository;
        this.tokenRepository = tokenRepository;
        this.emailService = emailService;
        this.appProperties = appProperties;
        this.clock = clock;
    }

    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final Pattern PASSWORD_SPECIAL = Pattern.compile("[!@#$%^&*(),.?\":{}|<>]");
    private static final Pattern PASSWORD_NUMBER = Pattern.compile("[0-9]");
    private static final Pattern PASSWORD_UPPERCASE = Pattern.compile("[A-Z]");

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        if (!EMAIL_PATTERN.matcher(request.getEmail()).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }

        validatePasswordStrength(request.getPassword());

        if (userRepository.existsByUsernameIgnoreCase(request.getUsername())) {
            throw new IllegalArgumentException("Username is already taken");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already in use");
        }

        
        
        Role defaultRole = roleRepository.findByRoleNameIgnoreCase("CUSTOMER")
                .orElseThrow(() -> new IllegalStateException("Default role not found"));

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        if (request.getFirstName() != null && !request.getFirstName().isBlank()) {
            user.setFirstName(request.getFirstName());
        } else {
            user.setFirstName(null);
        }

        if (request.getLastName() != null && !request.getLastName().isBlank()) {
            user.setLastName(request.getLastName());
        } else {
            user.setLastName(null);
        }
        user.setRole(defaultRole);
        user.setIsActive(false);
        user.setCreatedAt(LocalDateTime.now());

        userRepository.save(user);

        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setExpiryDate(LocalDateTime.now().plusHours(appProperties.getToken().getExpirationHours()));

        tokenRepository.save(verificationToken);

        emailService.sendVerificationEmail(user.getEmail(), token);
    }

    @Override
    @Transactional
    public void resendVerification(String email) {
        String normalizedEmail = email == null ? "" : email.trim();
        Optional<User> userOpt = userRepository.findByEmail(normalizedEmail);
        if (userOpt.isEmpty()) return;

        User user = userOpt.get();
        if (Boolean.TRUE.equals(user.getIsActive()) || user.isEmailVerified()) return;

        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = tokenRepository.findByUser(user).orElseGet(VerificationToken::new);
        verificationToken.setToken(token);
        verificationToken.setUser(user);
        verificationToken.setExpiryDate(LocalDateTime.now().plusHours(appProperties.getToken().getExpirationHours()));
        tokenRepository.save(verificationToken);
        emailService.sendVerificationEmail(user.getEmail(), token);
    }

    public boolean verifyEmail(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token expired");
        }

        User user = verificationToken.getUser();
        user.setIsActive(true);
        user.setEmailVerified(true);
        userRepository.save(user);

        tokenRepository.delete(verificationToken);
        return true;
    }

    @Override
    public void createSession(String token, String username, String ipAddress) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String tokenFingerprint = SessionTokenFingerprint.from(token);

        Session session = new Session();
        session.setUser(user);
        session.setTokenFingerprint(tokenFingerprint);
        session.setLoginTime(LocalDateTime.now(clock));
        session.setExpiryTime(LocalDateTime.now(clock).plusHours(2));
        session.setIsActive(true);
        session.setIpAddress(ipAddress);

        sessionRepository.save(session);
    }

    @Override
    public boolean isSessionValid(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        String tokenFingerprint = SessionTokenFingerprint.from(token);
        return sessionRepository.findByTokenFingerprint(tokenFingerprint)
                .map(session -> Boolean.TRUE.equals(session.getIsActive())
                        && session.getExpiryTime() != null
                        && session.getExpiryTime().isAfter(LocalDateTime.now(clock)))
                .orElse(false);
    }

    @Override
    public void logout(String token) {
        if (token == null || token.isBlank()) {
            throw new RuntimeException("Invalid session or already logged out.");
        }
        String tokenFingerprint = SessionTokenFingerprint.from(token);
        Optional<Session> sessionOpt = sessionRepository.findByTokenFingerprint(tokenFingerprint);
        if (sessionOpt.isPresent()) {
            Session session = sessionOpt.get();
            if (!session.getIsActive()) {
                throw new RuntimeException("Session already logged out.");
            }
            session.setLogoutTime(LocalDateTime.now(clock));
            session.setIsActive(false);
            sessionRepository.save(session);
        } else {
            throw new RuntimeException("Invalid session or already logged out.");
        }
    }

    public void validatePasswordStrength(String password) {
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }
        if (!PASSWORD_SPECIAL.matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }
        if (!PASSWORD_NUMBER.matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one number");
        }
        if (!PASSWORD_UPPERCASE.matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
    }

    @Override
    @Transactional
    public void changePassword(String username, ChangePasswordRequest request) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        if (request.getNewPassword().equals(request.getCurrentPassword())) {
            throw new IllegalArgumentException("New password cannot be the same as the current password");
        }

        validatePasswordStrength(request.getNewPassword());

        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Phase 4A P1-2: Invalidate all existing sessions for this user
        sessionRepository.deleteByUserUserId(user.getUserId());
    }

    @Override
    @Transactional
    public void revokeAllSessions(UUID userId) {
        if (userId != null) {
            sessionRepository.deleteByUserUserId(userId);
        }
    }
}
