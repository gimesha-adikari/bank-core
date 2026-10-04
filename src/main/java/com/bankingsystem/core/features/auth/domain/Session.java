package com.bankingsystem.core.features.auth.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "sessions")
public class Session {

    @Id
    @GeneratedValue
    @Column(name = "session_id", columnDefinition = "BINARY(16)")
    private UUID sessionId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token", nullable = false, unique = true, length = 255)
    private String tokenFingerprint;

    @Column(name = "login_time", nullable = false)
    private LocalDateTime loginTime;

    @Column(name = "logout_time")
    private LocalDateTime logoutTime;

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    // Getters and setters

    public UUID getSessionId() {
        return sessionId;
    }

    public void setSessionId(UUID sessionId) {
        this.sessionId = sessionId;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getTokenFingerprint() {
        return tokenFingerprint;
    }

    public void setTokenFingerprint(String tokenFingerprint) {
        this.tokenFingerprint = tokenFingerprint;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }

    public LocalDateTime getLogoutTime() {
        return logoutTime;
    }

    public void setLogoutTime(LocalDateTime logoutTime) {
        this.logoutTime = logoutTime;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean active) {
        isActive = active;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
