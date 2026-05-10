package com.cybershield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

/**
 * ================================================================
 * Alert - Entity Class
 * ================================================================
 *
 * PURPOSE:
 * Represents a security alert detected by the Intrusion
 * Detection System (IDS) in CyberShield CSMS.
 * Maps to the "ids_alerts" table in MySQL database.
 *
 * Alerts are created automatically when the system detects
 * suspicious or malicious network activity such as:
 *   - Port scanning attempts
 *   - Brute force login attacks
 *   - Known malicious IP connections
 *   - Unusual traffic patterns
 *   - Honeypot access attempts
 *
 * RESOLUTION:
 * isResolved = false → alert needs attention
 * isResolved = true  → alert has been reviewed by analyst
 *
 * SEVERITY LEVELS:
 *   LOW      → informational, monitor only
 *   MEDIUM   → suspicious, investigate soon
 *   HIGH     → serious threat, investigate now
 *   CRITICAL → active attack, immediate action
 *
 * INHERITANCE:
 * Extends BaseEntity — automatically gets:
 *   - id         (primary key)
 *   - createdAt  (when alert record was saved)
 *   - updatedAt  (when alert was last modified)
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@Entity
@Table(name = "ids_alerts")
public class Alert extends BaseEntity {

    // ================================================================
    // FIELDS — All private (ENCAPSULATION)
    // ================================================================

    /**
     * The type/category of this security alert.
     * Classifies what kind of attack or threat was detected.
     * Example values:
     *   "PORT_SCAN"
     *   "BRUTE_FORCE"
     *   "HONEYPOT_ACCESS"
     *   "MALICIOUS_IP"
     *   "DDOS_ATTEMPT"
     */
    @Column(name = "alert_type")
    private String alertType;

    /**
     * The IP address that triggered this alert.
     * The source of the suspicious or malicious activity.
     * Used to create firewall block rules automatically.
     * Example: "45.33.32.156" (known scanner IP)
     */
    @Column(name = "source_ip")
    private String sourceIP;

    /**
     * The network port that was targeted in this alert.
     * Null if alert does not relate to a specific port.
     * Example: 22 (SSH attack), 3306 (MySQL attack)
     */
    @Column(name = "target_port")
    private Integer targetPort;

    /**
     * How serious this alert is.
     * Determines urgency of response needed.
     * Values: "LOW", "MEDIUM", "HIGH", "CRITICAL"
     */
    @Column(name = "severity")
    private String severity;

    /**
     * Full human readable description of the alert.
     * Should give analyst enough detail to investigate.
     * Example: "Port scan detected from 45.33.32.156
     * targeting 1000 ports in under 10 seconds"
     */
    @Column(name = "description", length = 1000)
    private String description;

    /**
     * The exact date and time this alert was detected.
     * Set automatically by @PrePersist.
     * Never set this manually.
     * Example: 2024-01-15T02:30:00
     */
    @Column(name = "detected_at")
    private LocalDateTime detectedAt;

    /**
     * Whether this alert has been reviewed and resolved.
     * Default: false (unresolved when first created).
     * Analyst sets to true after investigating alert.
     * false → needs attention ⚠️
     * true  → reviewed and handled ✅
     */
    @Column(name = "is_resolved")
    private boolean isResolved;


    // ================================================================
    // CONSTRUCTOR
    // ================================================================

    /**
     * No-argument constructor required by JPA.
     * Sets isResolved to false by default —
     * every new alert starts as unresolved.
     */
    public Alert() {
        this.isResolved = false;
    }


    // ================================================================
    // JPA LIFECYCLE METHOD
    // ================================================================

    /**
     * @PrePersist — runs automatically BEFORE this alert
     * is saved to database for the first time.
     * Sets detectedAt to exact current date and time.
     * You never call this manually.
     */
    @PrePersist
    protected void onCreate() {
        this.detectedAt = LocalDateTime.now();
    }


    // ================================================================
    // GETTERS AND SETTERS — ENCAPSULATION
    // ================================================================

    /**
     * Returns the type of this security alert.
     * @return String alertType
     */
    public String getAlertType() {
        return alertType;
    }

    /**
     * Sets the type of this security alert.
     * @param alertType category of the threat detected
     */
    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    /**
     * Returns the source IP that triggered this alert.
     * @return String sourceIP
     */
    public String getSourceIP() {
        return sourceIP;
    }

    /**
     * Sets the source IP that triggered this alert.
     * @param sourceIP attacking or suspicious IP address
     */
    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    /**
     * Returns the targeted port number of this alert.
     * @return Integer targetPort or null
     */
    public Integer getTargetPort() {
        return targetPort;
    }

    /**
     * Sets the targeted port number of this alert.
     * @param targetPort port that was attacked or scanned
     */
    public void setTargetPort(Integer targetPort) {
        this.targetPort = targetPort;
    }

    /**
     * Returns the severity level of this alert.
     * @return String severity
     */
    public String getSeverity() {
        return severity;
    }

    /**
     * Sets the severity level of this alert.
     * @param severity LOW, MEDIUM, HIGH, or CRITICAL
     */
    public void setSeverity(String severity) {
        this.severity = severity;
    }

    /**
     * Returns the full description of this alert.
     * @return String description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the full description of this alert.
     * @param description detailed explanation of the threat
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Returns when this alert was detected.
     * @return LocalDateTime detectedAt
     */
    public LocalDateTime getDetectedAt() {
        return detectedAt;
    }

    /**
     * Sets when this alert was detected.
     * Note: normally set automatically by @PrePersist.
     * @param detectedAt detection timestamp
     */
    public void setDetectedAt(LocalDateTime detectedAt) {
        this.detectedAt = detectedAt;
    }

    /**
     * Returns whether this alert has been resolved.
     * @return true if resolved, false if still open
     */
    public boolean isResolved() {
        return isResolved;
    }

    /**
     * Sets whether this alert has been resolved.
     * @param isResolved true when analyst has handled alert
     */
    public void setResolved(boolean isResolved) {
        this.isResolved = isResolved;
    }

}