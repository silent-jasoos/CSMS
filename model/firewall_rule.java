package com.cybershield.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * ================================================================
 * FirewallRule - Entity Class
 * ================================================================
 *
 * PURPOSE:
 * Represents a single firewall rule in the CyberShield CSMS.
 * Maps to the "firewall_rules" table in MySQL database.
 *
 * Each rule defines whether network traffic from a specific
 * IP address and port should be ALLOWED or BLOCKED.
 *
 * RULE PRIORITY:
 * Rules are evaluated in priority order (1 = highest priority).
 * If two rules conflict, the higher priority rule wins.
 * Example: priority 1 BLOCK overrides priority 10 ALLOW.
 *
 * INHERITANCE:
 * Extends BaseEntity — automatically gets:
 *   - id         (primary key)
 *   - createdAt  (when rule was created)
 *   - updatedAt  (when rule was last modified)
 *
 * ENCAPSULATION:
 * All fields private — accessed only through getters/setters.
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@Entity
@Table(name = "firewall_rules")
public class FirewallRule extends BaseEntity {

    // ================================================================
    // FIELDS — All private (ENCAPSULATION)
    // ================================================================

    /**
     * Human readable name for this firewall rule.
     * Used to identify the rule in the UI.
     * Example: "Block China IPs", "Allow Office Network"
     */
    @Column(name = "rule_name")
    private String ruleName;

    /**
     * The IP address this rule applies to.
     * Supports wildcards for range matching.
     * Example exact:    "192.168.1.100"
     * Example wildcard: "192.168.*"  (entire subnet)
     * Example wildcard: "10.*"       (entire range)
     */
    @Column(name = "ip_address")
    private String ipAddress;

    /**
     * The network port number this rule applies to.
     * Common ports:
     *   80   → HTTP
     *   443  → HTTPS
     *   22   → SSH
     *   3306 → MySQL
     * Null means rule applies to ALL ports.
     */
    @Column(name = "port_number")
    private Integer portNumber;

    /**
     * The network protocol this rule applies to.
     * Accepted values:
     *   "TCP"  → Transmission Control Protocol
     *   "UDP"  → User Datagram Protocol
     *   "BOTH" → applies to both TCP and UDP
     */
    @Column(name = "protocol")
    private String protocol;

    /**
     * The action to take when this rule matches traffic.
     * Accepted values:
     *   "ALLOW" → let the traffic through
     *   "BLOCK" → drop/reject the traffic
     */
    @Column(name = "action")
    private String action;

    /**
     * Priority of this rule (1 = highest, 100 = lowest).
     * When multiple rules match the same traffic,
     * the rule with lowest number (highest priority) wins.
     * Example: priority 1 BLOCK beats priority 50 ALLOW.
     */
    @Column(name = "priority")
    private Integer priority;

    /**
     * Whether this firewall rule is currently active.
     * Inactive rules are ignored during traffic evaluation.
     * Default: true (active when first created).
     * Allows disabling rules without deleting them.
     */
    @Column(name = "is_active")
    private boolean isActive;

    /**
     * Username of the admin who created this rule.
     * Used for audit trail — who created which rule.
     * Example: "ahmed_admin"
     */
    @Column(name = "created_by")
    private String createdBy;


    // ================================================================
    // CONSTRUCTOR
    // ================================================================

    /**
     * No-argument constructor required by JPA.
     * Sets default values for boolean fields.
     */
    public FirewallRule() {
        this.isActive = true;
    }


    // ================================================================
    // GETTERS AND SETTERS — ENCAPSULATION
    // ================================================================

    /**
     * Returns the name of this firewall rule.
     * @return String ruleName
     */
    public String getRuleName() {
        return ruleName;
    }

    /**
     * Sets the name of this firewall rule.
     * @param ruleName human readable rule name
     */
    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    /**
     * Returns the IP address pattern this rule applies to.
     * @return String ipAddress (supports wildcards)
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * Sets the IP address pattern for this rule.
     * Supports wildcards e.g. "192.168.*"
     * @param ipAddress the IP address or pattern
     */
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    /**
     * Returns the port number this rule applies to.
     * Returns null if rule applies to all ports.
     * @return Integer portNumber or null
     */
    public Integer getPortNumber() {
        return portNumber;
    }

    /**
     * Sets the port number this rule applies to.
     * Pass null to apply rule to all ports.
     * @param portNumber the port number to set
     */
    public void setPortNumber(Integer portNumber) {
        this.portNumber = portNumber;
    }

    /**
     * Returns the protocol this rule applies to.
     * @return String "TCP", "UDP", or "BOTH"
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Sets the protocol this rule applies to.
     * @param protocol "TCP", "UDP", or "BOTH"
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    /**
     * Returns the action taken when this rule matches.
     * @return String "ALLOW" or "BLOCK"
     */
    public String getAction() {
        return action;
    }

    /**
     * Sets the action for this rule.
     * @param action "ALLOW" or "BLOCK"
     */
    public void setAction(String action) {
        this.action = action;
    }

    /**
     * Returns the priority of this rule.
     * @return Integer priority (1=highest, 100=lowest)
     */
    public Integer getPriority() {
        return priority;
    }

    /**
     * Sets the priority of this rule.
     * @param priority value between 1 and 100
     */
    public void setPriority(Integer priority) {
        this.priority = priority;
    }

    /**
     * Returns whether this rule is currently active.
     * @return true if active, false if disabled
     */
    public boolean isActive() {
        return isActive;
    }

    /**
     * Sets whether this rule is active or disabled.
     * @param isActive true to enable, false to disable
     */
    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }

    /**
     * Returns the username of who created this rule.
     * @return String createdBy username
     */
    public String getCreatedBy() {
        return createdBy;
    }

    /**
     * Sets the username of who created this rule.
     * @param createdBy admin username who created rule
     */
    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

}