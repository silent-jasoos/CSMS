package com.cybershield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

/**
 * ================================================================
 * LogEntry - Entity Class
 * ================================================================
 *
 * PURPOSE:
 * Represents a single system event log in CyberShield CSMS.
 * Maps to the "log_entries" table in MySQL database.
 *
 * Every important action in the system creates a LogEntry:
 *   - User login / logout
 *   - Firewall rule changes
 *   - Failed login attempts
 *   - Alert triggered
 *   - System configuration changes
 *
 * TIMESTAMP:
 * Set automatically via @PrePersist when log is saved.
 * You never set timestamp manually.
 *
 * SEVERITY LEVELS:
 *   INFO     → normal activity
 *   WARNING  → suspicious but not critical
 *   ERROR    → something went wrong
 *   CRITICAL → immediate attention required
 *
 * INHERITANCE:
 * Extends BaseEntity — automatically gets:
 *   - id         (primary key)
 *   - createdAt  (when log was saved)
 *   - updatedAt  (when log was modified)
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@Entity
@Table(name = "log_entries")
public class LogEntry extends BaseEntity {

    // ================================================================
    // FIELDS — All private (ENCAPSULATION)
    // ================================================================

    /**
     * The exact date and time this event occurred.
     * Set automatically by @PrePersist.
     * Never set this manually.
     * Example: 2024-01-15T10:30:45
     */
    @Column(name = "timestamp")
    private LocalDateTime timestamp;

    /**
     * The type/category of this event.
     * Used for filtering and searching logs.
     * Example values:
     *   "LOGIN_SUCCESS"
     *   "LOGIN_FAILED"
     *   "FIREWALL_RULE_ADDED"
     *   "ALERT_TRIGGERED"
     *   "USER_CREATED"
     */
    @Column(name = "event_type")
    private String eventType;

    /**
     * The IP address where this event originated from.
     * Helps identify which machine triggered the event.
     * Supports both IPv4 and IPv6.
     * Example: "192.168.1.100"
     */
    @Column(name = "source_ip")
    private String sourceIP;

    /**
     * The module or component of the system affected.
     * Helps identify which part of the system the event relates to.
     * Example values:
     *   "AuthModule"
     *   "FirewallModule"
     *   "AlertModule"
     *   "UserManagement"
     */
    @Column(name = "target_module")
    private String targetModule;

    /**
     * How serious this log event is.
     * Used for filtering and color coding in UI.
     * Values: "INFO", "WARNING", "ERROR", "CRITICAL"
     */
    @Column(name = "severity")
    private String severity;

    /**
     * The username of the user who triggered this event.
     * Null if event was triggered by the system automatically.
     * Example: "ahmed_admin", "sara_analyst"
     */
    @Column(name = "username")
    private String username;

    /**
     * Full human readable description of what happened.
     * Should be clear enough for an admin to understand.
     * Example: "User ahmed_admin logged in from 192.168.1.5"
     * Example: "Firewall rule Block China IPs was modified"
     */
    @Column(name = "description", length = 1000)
    private String description;

    /**
     * The name of the machine/computer where event occurred.
     * Helps identify which device in the network triggered event.
     * Example: "DESKTOP-ABC123", "SERVER-MAIN", "LAPTOP-HR01"
     */
    @Column(name = "machine_name")
    private String machineName;


    // ================================================================
    // CONSTRUCTOR
    // ================================================================

    /**
     * No-argument constructor required by JPA.
     */
    public LogEntry() {
    }


    // ================================================================
    // JPA LIFECYCLE METHOD
    // ================================================================

    /**
     * @PrePersist — runs automatically BEFORE this log entry
     * is saved to database for the first time.
     * Sets timestamp to exact current date and time.
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
     * Returns the timestamp of this log event.
     * @return LocalDateTime timestamp
     */
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    /**
     * Sets the timestamp of this log event.
     * Note: normally set automatically by @PrePersist.
     * @param timestamp the event timestamp
     */
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Returns the type of this log event.
     * @return String eventType
     */
    public String getEventType() {
        return eventType;
    }

    /**
     * Sets the type of this log event.
     * @param eventType category of the event
     */
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    /**
     * Returns the source IP address of this event.
     * @return String sourceIP
     */
    public String getSourceIP() {
        return sourceIP;
    }

    /**
     * Sets the source IP address of this event.
     * @param sourceIP originating IP address
     */
    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    /**
     * Returns the target module affected by this event.
     * @return String targetModule
     */
    public String getTargetModule() {
        return targetModule;
    }

    /**
     * Sets the target module affected by this event.
     * @param targetModule system module name
     */
    public void setTargetModule(String targetModule) {
        this.targetModule = targetModule;
    }

    /**
     * Returns the severity level of this log event.
     * @return String severity
     */
    public String getSeverity() {
        return severity;
    }

    /**
     * Sets the severity level of this log event.
     * @param severity INFO, WARNING, ERROR, or CRITICAL
     */
    public void setSeverity(String severity) {
        this.severity = severity;
    }

    /**
     * Returns the username who triggered this event.
     * @return String username or null
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username who triggered this event.
     * @param username the user's login name
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the full description of this event.
     * @return String description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the full description of this event.
     * @param description human readable event details
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Returns the machine name where event occurred.
     * @return String machineName
     */
    public String getMachineName() {
        return machineName;
    }

    /**
     * Sets the machine name where event occurred.
     * @param machineName computer/device name
     */
    public void setMachineName(String machineName) {
        this.machineName = machineName;
    }

}