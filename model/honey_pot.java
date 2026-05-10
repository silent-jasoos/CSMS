package com.cybershield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

/**
 * ================================================================
 * HoneypotCapture - Entity Class
 * ================================================================
 *
 * PURPOSE:
 * Represents credentials and information captured by the
 * CyberShield honeypot system.
 * Maps to the "honeypot_captures" table in MySQL database.
 *
 * WHAT IS A HONEYPOT?
 * A honeypot is a fake system that looks like a real target.
 * Attackers try to break into it thinking it is real.
 * Everything they do is secretly recorded as evidence.
 *
 * When an attacker connects to the honeypot and tries
 * to log in, their IP, username attempt, password attempt,
 * browser info and session duration are all captured here.
 *
 * HOW IT IS USED:
 * 1. Captured IPs are added to firewall block rules
 * 2. Captured credentials show attacker tactics
 * 3. Data is used to improve real system defenses
 * 4. Evidence can be used for legal/forensic purposes
 *
 * IMPORTANT SECURITY NOTE:
 * Unlike real user passwords which are BCrypt hashed,
 * honeypot captured passwords are stored as PLAIN TEXT.
 * This is INTENTIONAL — we want to see exactly what
 * passwords attackers are trying so we can analyze
 * their attack patterns and tactics.
 *
 * INHERITANCE:
 * Extends BaseEntity — automatically gets:
 *   - id         (primary key)
 *   - createdAt  (when capture was saved)
 *   - updatedAt  (when capture was modified)
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@Entity
@Table(name = "honeypot_captures")
public class HoneypotCapture extends BaseEntity {

    // ================================================================
    // FIELDS — All private (ENCAPSULATION)
    // ================================================================

    /**
     * The IP address of the attacker who connected
     * to the honeypot system.
     * Used to automatically create firewall block rules.
     * Can be traced back to attacker's location.
     * Example: "45.33.32.156"
     */
    @Column(name = "captured_ip")
    private String capturedIP;

    /**
     * The username the attacker attempted to use
     * when trying to log into the honeypot.
     * Reveals which usernames attackers commonly try.
     * Example: "admin", "root", "administrator", "user"
     */
    @Column(name = "captured_username")
    private String capturedUsername;

    /**
     * The password the attacker attempted to use
     * when trying to log into the honeypot.
     *
     * ⚠️ SECURITY NOTE — PLAIN TEXT INTENTIONAL:
     * This field stores passwords in PLAIN TEXT.
     * This is deliberately done because:
     *   1. These are NOT real user passwords
     *   2. We need to analyze exact attack patterns
     *   3. Common password lists attackers use
     *   4. This data serves as attack evidence
     *
     * Example: "password123", "admin", "123456"
     * These reveal common passwords in attack dictionaries.
     */
    @Column(name = "captured_password")
    private String capturedPassword;

    /**
     * Browser and system information of the attacker.
     * Captured from HTTP headers automatically.
     * Reveals what tools and OS the attacker is using.
     * Example: "Mozilla/5.0 ... (automated scanner)"
     * Example: "sqlmap/1.7" (reveals SQL injection tool)
     */
    @Column(name = "browser_info", length = 500)
    private String browserInfo;

    /**
     * The exact date and time the attacker connected
     * to the honeypot system.
     * Set automatically by @PrePersist.
     * Never set this manually.
     * Example: 2024-01-15T03:22:10
     */
    @Column(name = "timestamp")
    private LocalDateTime timestamp;

    /**
     * How long the attacker stayed connected to
     * the honeypot in seconds.
     * Longer sessions suggest manual human attackers.
     * Shorter sessions suggest automated attack tools.
     * Example: 5   → automated tool (very fast)
     * Example: 300 → human attacker (5 minutes)
     */
    @Column(name = "session_duration_seconds")
    private Long sessionDurationSeconds;


    // ================================================================
    // CONSTRUCTOR
    // ================================================================

    /**
     * No-argument constructor required by JPA.
     */
    public HoneypotCapture() {
    }


    // ================================================================
    // JPA LIFECYCLE METHOD
    // ================================================================

    /**
     * @PrePersist — runs automatically BEFORE this capture
     * is saved to database for the first time.
     * Sets timestamp to exact current date and time
     * of when the attacker connected.
     * You never call this manually.
     */
    @PrePersist
    protected void onCreate() {
        this.timestamp = LocalDateTime.now();
    }


    // ================================================================
    // GETTERS AND SETTERS — ENCAPSULATION
    // ================================================================

    /**
     * Returns the captured IP address of the attacker.
     * @return String capturedIP
     */
    public String getCapturedIP() {
        return capturedIP;
    }

    /**
     * Sets the captured IP address of the attacker.
     * @param capturedIP attacker's IP address
     */
    public void setCapturedIP(String capturedIP) {
        this.capturedIP = capturedIP;
    }

    /**
     * Returns the username the attacker attempted.
     * @return String capturedUsername
     */
    public String getCapturedUsername() {
        return capturedUsername;
    }

    /**
     * Sets the username the attacker attempted.
     * @param capturedUsername attempted login username
     */
    public void setCapturedUsername(String capturedUsername) {
        this.capturedUsername = capturedUsername;
    }

    /**
     * Returns the plain text password the attacker attempted.
     * Stored plain text intentionally as attack evidence.
     * @return String capturedPassword
     */
    public String getCapturedPassword() {
        return capturedPassword;
    }

    /**
     * Sets the plain text password the attacker attempted.
     * Intentionally stored as plain text for analysis.
     * @param capturedPassword attempted login password
     */
    public void setCapturedPassword(String capturedPassword) {
        this.capturedPassword = capturedPassword;
    }

    /**
     * Returns the browser and tool info of the attacker.
     * @return String browserInfo
     */
    public String getBrowserInfo() {
        return browserInfo;
    }

    /**
     * Sets the browser and tool info of the attacker.
     * @param browserInfo HTTP user-agent string captured
     */
    public void setBrowserInfo(String browserInfo) {
        this.browserInfo = browserInfo;
    }

    /**
     * Returns when the attacker connected to honeypot.
     * @return LocalDateTime timestamp
     */
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    /**
     * Sets when the attacker connected to honeypot.
     * Note: normally set automatically by @PrePersist.
     * @param timestamp connection timestamp
     */
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Returns how long attacker stayed connected in seconds.
     * @return Long sessionDurationSeconds
     */
    public Long getSessionDurationSeconds() {
        return sessionDurationSeconds;
    }

    /**
     * Sets how long attacker stayed connected in seconds.
     * @param sessionDurationSeconds connection duration
     */
    public void setSessionDurationSeconds(Long sessionDurationSeconds) {
        this.sessionDurationSeconds = sessionDurationSeconds;
    }

}