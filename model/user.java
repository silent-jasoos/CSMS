package com.cybershield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

/**
 * ================================================================
 * User - Entity Class
 * ================================================================
 *
 * PURPOSE:
 * Represents a user account in the CyberShield CSMS system.
 * Maps to the "users" table in MySQL database.
 *
 * OOP PRINCIPLE DEMONSTRATED:
 * ENCAPSULATION — All fields are private and cannot be accessed
 * directly from outside this class. Every field is accessed
 * and modified only through public getters and setters.
 *
 * This means:
 *   ❌ user.password = "abc"         → NOT allowed
 *   ✅ user.setPassword("abc")       → allowed through setter
 *   ✅ user.getPassword()            → allowed through getter
 *
 * INHERITANCE:
 * Extends BaseEntity which automatically provides:
 *   - id          (primary key, auto generated)
 *   - createdAt   (when user was created)
 *   - updatedAt   (when user was last updated)
 *
 * ROLES:
 * Each user has one Role (ADMIN, ANALYST, VIEWER)
 * which controls what they can access in the system.
 *
 * SECURITY FEATURES:
 * - failedLoginAttempts tracks brute force attempts
 * - lockedUntil locks account after too many failures
 * - lastLoginAt tracks when user last logged in
 * - lastLoginIP tracks where user logged in from
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@Entity
@Table(name = "users")
public class User extends BaseEntity {

    // ================================================================
    // FIELDS — All private (ENCAPSULATION)
    // ================================================================

    /**
     * The unique username for this user account.
     * Used for logging into the CyberShield system.
     * Cannot be null, must be unique across all users.
     * Maximum 50 characters.
     * Example: "ahmed_admin", "sara_analyst"
     */
    @Column(name = "username", unique = true, nullable = false, length = 50)
    private String username;

    /**
     * The hashed password for this user account.
     * NEVER stored as plain text — always BCrypt hashed.
     * Cannot be null.
     * Length 255 to accommodate BCrypt hash format.
     * Example (hashed): "$2a$10$xyzabc..."
     */
    @Column(name = "password", nullable = false, length = 255)
    private String password;

    /**
     * The email address of this user.
     * Used for notifications and password reset.
     * Must be unique across all users.
     * Maximum 100 characters.
     * Example: "ahmed@cybershield.com"
     */
    @Column(name = "email", unique = true, length = 100)
    private String email;

    /**
     * The access role assigned to this user.
     * Determines what this user can see and do.
     * Stored as String in database (EnumType.STRING).
     * Example values in DB: "ADMIN", "ANALYST", "VIEWER"
     *
     * ADMIN   → full system access
     * ANALYST → view and analyze only
     * VIEWER  → monitoring access only
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "role")
    private Role role;

    /**
     * Whether this user account is currently active.
     * Inactive users cannot log in to the system.
     * Default: true (active when first created).
     * Admin can deactivate accounts without deleting them.
     * Example: true = can login, false = cannot login
     */
    @Column(name = "is_active")
    private boolean isActive;

    /**
     * Number of consecutive failed login attempts.
     * Resets to 0 on successful login.
     * Default: 0 (no failed attempts when first created).
     * When this reaches limit (e.g. 5), account gets locked.
     * Used to prevent brute force password attacks.
     * Example: 0, 1, 2, 3, 4, 5 → locked
     */
    @Column(name = "failed_login_attempts")
    private int failedLoginAttempts;

    /**
     * The date and time until which this account is locked.
     * Null means account is not locked.
     * Set automatically when failedLoginAttempts reaches limit.
     * After this time passes, user can try logging in again.
     * Example: 2024-01-15T10:30:00 (locked until this time)
     */
    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    /**
     * The date and time of the user's most recent login.
     * Null if user has never logged in.
     * Updated automatically on every successful login.
     * Used for security auditing and monitoring.
     * Example: 2024-01-15T09:00:00
     */
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    /**
     * The IP address from which the user last logged in.
     * Null if user has never logged in.
     * Length 45 to support both IPv4 and IPv6 addresses.
     * Used for security auditing and detecting suspicious logins.
     * Example IPv4: "192.168.1.1"
     * Example IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
     */
    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIP;


    // ================================================================
    // CONSTRUCTORS
    // ================================================================

    /**
     * No-argument constructor — REQUIRED by JPA.
     * JPA needs this to create User objects when
     * loading data from the database.
     *
     * Sets safe default values:
     * isActive = true  → account active by default
     * failedLoginAttempts = 0 → no failed attempts by default
     */
    public User() {
        this.isActive = true;
        this.failedLoginAttempts = 0;
    }


    // ================================================================
    // GETTERS AND SETTERS
    // ENCAPSULATION — private fields accessed through
    // public methods only. Code outside User.java must
    // use user.getPassword() not user.password
    // ================================================================

    /**
     * Returns the username of this user.
     * @return String username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username of this user.
     * Username is used to log in to the system.
     * @param username the username to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the password of this user.
     * Note: This returns the BCrypt hashed password,
     * never the plain text password.
     * @return String hashed password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password of this user.
     * Important: Always pass BCrypt hashed password here.
     * Never store plain text passwords.
     * Example: setPassword(bCryptEncoder.encode("plaintext"))
     * @param password the hashed password to set
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Returns the email address of this user.
     * @return String email
     */
    public String getEmail() {
        return email;
    }

    /**
     * Sets the email address of this user.
     * Used for notifications and password reset emails.
     * @param email the email address to set
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Returns the role of this user.
     * Role determines access level in the system.
     * @return Role enum value (ADMIN, ANALYST, VIEWER)
     */
    public Role getRole() {
        return role;
    }

    /**
     * Sets the role of this user.
     * Controls what this user can see and do.
     * @param role the Role to assign (ADMIN, ANALYST, VIEWER)
     */
    public void setRole(Role role) {
        this.role = role;
    }

    /**
     * Returns whether this user account is active.
     * @return true if active, false if deactivated
     */
    public boolean isActive() {
        return isActive;
    }

    /**
     * Sets whether this user account is active or not.
     * Set to false to deactivate without deleting account.
     * @param isActive true to activate, false to deactivate
     */
    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }

    /**
     * Returns the number of consecutive failed login attempts.
     * @return int number of failed attempts
     */
    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    /**
     * Sets the number of failed login attempts.
     * Set to 0 on successful login.
     * Increment by 1 on each failed login.
     * @param failedLoginAttempts the count to set
     */
    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    /**
     * Returns the date and time until which account is locked.
     * Returns null if account is not currently locked.
     * @return LocalDateTime lockedUntil or null
     */
    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    /**
     * Sets the date and time until which account is locked.
     * Pass null to unlock the account.
     * Example: setLockedUntil(LocalDateTime.now().plusMinutes(30))
     * locks account for 30 minutes.
     * @param lockedUntil the unlock datetime to set
     */
    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    /**
     * Returns the date and time of last successful login.
     * Returns null if user has never logged in.
     * @return LocalDateTime lastLoginAt or null
     */
    public LocalDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    /**
     * Sets the date and time of last successful login.
     * Call this on every successful login.
     * Example: setLastLoginAt(LocalDateTime.now())
     * @param lastLoginAt the login timestamp to set
     */
    public void setLastLoginAt(LocalDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    /**
     * Returns the IP address of last successful login.
     * Returns null if user has never logged in.
     * @return String IP address or null
     */
    public String getLastLoginIP() {
        return lastLoginIP;
    }

    /**
     * Sets the IP address of last successful login.
     * Call this on every successful login.
     * Supports both IPv4 and IPv6 addresses.
     * Example: setLastLoginIP("192.168.1.1")
     * @param lastLoginIP the IP address to set
     */
    public void setLastLoginIP(String lastLoginIP) {
        this.lastLoginIP = lastLoginIP;
    }

}