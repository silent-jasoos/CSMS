package com.cybershield.service;

import com.cybershield.model.LogEntry;
import com.cybershield.repository.LogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Central event-logging service for the CyberShield security platform.
 *
 * <p><b>SINGLETON:</b> Spring {@code @Service} creates exactly one instance
 * of this class in the application context. Every module that needs to record
 * a security event injects the same object, guaranteeing a single, consistent
 * write path to the {@code log_entries} table.
 *
 * <p><b>OBSERVER:</b> All modules (Auth, Firewall, IDS, Honeypot) call this
 * class when events occur. {@code AttackLogger} acts as the central observer
 * that reacts to every security-relevant event across the application by
 * persisting a structured {@link LogEntry} record. No module needs to know
 * how logs are stored — they simply call the appropriate convenience method
 * and this class handles the rest.
 *
 * <h2>Log entry anatomy</h2>
 * <p>Every log entry shares a common schema:
 * <ul>
 *   <li>{@code eventType} – machine-readable category (e.g. {@code LOGIN_SUCCESS})</li>
 *   <li>{@code sourceIP} – originating IP address for attribution</li>
 *   <li>{@code targetModule} – subsystem that generated the event</li>
 *   <li>{@code severity} – {@code INFO}, {@code LOW}, {@code MEDIUM},
 *       {@code HIGH}, or {@code CRITICAL}</li>
 *   <li>{@code username} – principal involved (may be {@code "SYSTEM"} if
 *       no user is associated)</li>
 *   <li>{@code description} – human-readable summary for the audit trail</li>
 *   <li>{@code machineName} – host that recorded the event (useful in
 *       multi-node deployments)</li>
 *   <li>{@code timestamp} – {@link LocalDateTime#now()} at write time</li>
 * </ul>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
@Service
public class AttackLogger {

    private static final Logger logger = LoggerFactory.getLogger(AttackLogger.class);

    /**
     * Repository used to persist {@link LogEntry} records to the
     * {@code log_entries} table.
     */
    private final LogRepository logRepository;

    /**
     * Constructs an {@code AttackLogger} with its required repository.
     *
     * @param logRepository the JPA repository for {@link LogEntry} persistence;
     *                      must not be {@code null}
     */
    public AttackLogger(LogRepository logRepository) {
        this.logRepository = logRepository;
    }

    // =========================================================================
    // Core persistence method
    // =========================================================================

    /**
     * Creates and persists a {@link LogEntry} capturing a complete security
     * event with all contextual fields.
     *
     * <p>This is the single write path for all log entries in CyberShield.
     * Every convenience method delegates to this method, ensuring a consistent
     * schema and timestamp strategy across all event types.
     *
     * <p>The {@code timestamp} is always set to {@link LocalDateTime#now()} at
     * invocation time, not at the time the triggering event occurred. For most
     * flows (synchronous request processing) these timestamps are
     * indistinguishable. Asynchronous callers should pass the original event
     * time via the {@code description} field if precision matters.
     *
     * @param eventType    machine-readable event category
     *                     (e.g. {@code "LOGIN_SUCCESS"}, {@code "FIREWALL_BLOCK"})
     * @param sourceIP     IP address of the client or origin system that caused
     *                     the event; use {@code "INTERNAL"} for system-generated events
     * @param targetModule the CyberShield subsystem recording the event
     *                     (e.g. {@code "AUTH"}, {@code "FIREWALL"}, {@code "IDS"})
     * @param severity     event severity level: {@code "INFO"}, {@code "LOW"},
     *                     {@code "MEDIUM"}, {@code "HIGH"}, or {@code "CRITICAL"}
     * @param username     the authenticated or attempted username involved in the
     *                     event; use {@code "SYSTEM"} when no user is applicable
     * @param description  free-text human-readable summary for the audit trail
     * @param machineName  hostname of the node recording the event, useful for
     *                     correlating logs in clustered deployments
     */
    public void logEvent(String eventType,
                         String sourceIP,
                         String targetModule,
                         String severity,
                         String username,
                         String description,
                         String machineName) {

        LogEntry entry = new LogEntry();
        entry.setEventType(eventType);
        entry.setSourceIP(sourceIP);
        entry.setTargetModule(targetModule);
        entry.setSeverity(severity);
        entry.setUsername(username);
        entry.setDescription(description);
        entry.setMachineName(machineName);
        entry.setTimestamp(LocalDateTime.now());

        logRepository.save(entry);

        logger.info("[{}] {} | IP={} | user={} | severity={} | {}",
                targetModule, eventType, sourceIP, username, severity, description);
    }

    // =========================================================================
    // Auth convenience methods
    // =========================================================================

    /**
     * Logs a successful user authentication.
     *
     * <p>Records the event with severity {@code "INFO"} because a successful
     * login is expected behaviour. The log is still valuable for session
     * auditing, detecting credential sharing across unexpected IPs, and
     * constructing user-behaviour baselines.
     *
     * @param username the username that successfully authenticated
     * @param ip       the IP address from which the login was performed
     */
    public void logLoginSuccess(String username, String ip) {
        logEvent(
                "LOGIN_SUCCESS",
                ip,
                "AUTH",
                "INFO",
                username,
                "Successful login for user: " + username + " from IP: " + ip,
                "CYBERSHIELD-SERVER"
        );
    }

    /**
     * Logs a failed authentication attempt, including the cumulative failure
     * count for the targeted account.
     *
     * <p>Recorded with severity {@code "MEDIUM"} — a single failure is
     * expected (mistyped password) but repeated failures indicate a
     * brute-force or credential-stuffing attempt.
     *
     * @param username  the username for which authentication failed
     * @param ip        the IP address from which the attempt originated
     * @param failCount the total number of consecutive failures recorded
     *                  for this account since the last successful login or unlock
     */
    public void logLoginFail(String username, String ip, int failCount) {
        logEvent(
                "LOGIN_FAIL",
                ip,
                "AUTH",
                "MEDIUM",
                username,
                "Failed login attempt #" + failCount + " for user: " + username
                        + " from IP: " + ip,
                "CYBERSHIELD-SERVER"
        );
    }

    /**
     * Logs an account being locked after exceeding the maximum consecutive
     * failed-login threshold.
     *
     * <p>Recorded with severity {@code "HIGH"} because an account lock
     * directly impacts user availability and is a strong indicator of an
     * active credential attack targeting that specific account.
     *
     * @param username the username of the account that was locked
     * @param ip       the IP address whose login failures triggered the lock
     */
    public void logAccountLocked(String username, String ip) {
        logEvent(
                "ACCOUNT_LOCKED",
                ip,
                "AUTH",
                "HIGH",
                username,
                "Account locked after repeated failed attempts. User: " + username
                        + " — triggered by IP: " + ip,
                "CYBERSHIELD-SERVER"
        );
    }

    // =========================================================================
    // Firewall convenience methods
    // =========================================================================

    /**
     * Logs a packet or connection blocked by the firewall engine.
     *
     * <p>Recorded with severity {@code "HIGH"} to ensure blocked traffic
     * appears prominently in the operations dashboard. The matched rule name
     * is included so analysts can determine whether the block was intentional
     * (e.g. IP blacklist) or potentially a false positive.
     *
     * @param ip          the source IP address of the blocked traffic
     * @param port        the destination port that was probed or targeted
     * @param matchedRule the name of the firewall rule that triggered the block
     */
    public void logFirewallBlock(String ip, int port, String matchedRule) {
        logEvent(
                "FIREWALL_BLOCK",
                ip,
                "FIREWALL",
                "HIGH",
                "SYSTEM",
                "Firewall blocked traffic from IP: " + ip + " on port " + port
                        + " — matched rule: [" + matchedRule + "]",
                "CYBERSHIELD-SERVER"
        );
    }

    /**
     * Logs a firewall rule creation, modification, or deletion by an admin user.
     *
     * <p>Recorded with severity {@code "INFO"} (expected administrative activity)
     * but this log is critical for change-management auditing — any unauthorised
     * rule modification could open network pathways for attackers.
     *
     * @param action    the performed action: {@code "CREATE"}, {@code "UPDATE"},
     *                  or {@code "DELETE"}
     * @param ruleName  the name or identifier of the affected firewall rule
     * @param adminUser the username of the administrator who made the change
     */
    public void logFirewallRuleChange(String action, String ruleName, String adminUser) {
        logEvent(
                "FIREWALL_RULE_CHANGE",
                "INTERNAL",
                "FIREWALL",
                "INFO",
                adminUser,
                "Firewall rule " + action + ": [" + ruleName + "] by admin: " + adminUser,
                "CYBERSHIELD-SERVER"
        );
    }

    // =========================================================================
    // IDS convenience method
    // =========================================================================

    /**
     * Logs an alert raised by the Intrusion Detection System.
     *
     * <p>The severity is passed through from the triggering {@code AttackPattern}
     * implementation, so it accurately reflects the alert type:
     * {@code "MEDIUM"} for port scans, {@code "HIGH"} for brute-force attempts,
     * and {@code "CRITICAL"} for SQL injection or DDoS floods.
     *
     * @param alertType the category of the detected attack
     *                  (e.g. {@code "BRUTE_FORCE"}, {@code "SQL_INJECTION"},
     *                  {@code "DDOS_ATTACK"}, {@code "PORT_SCAN"})
     * @param ip        the source IP address associated with the detected attack
     * @param severity  severity level forwarded from the detecting
     *                  {@code AttackPattern}: {@code "MEDIUM"}, {@code "HIGH"},
     *                  or {@code "CRITICAL"}
     */
    public void logIDSAlert(String alertType, String ip, String severity) {
        logEvent(
                "IDS_ALERT",
                ip,
                "IDS",
                severity,
                "SYSTEM",
                "IDS detected attack pattern [" + alertType + "] from IP: " + ip,
                "CYBERSHIELD-SERVER"
        );
    }

    // =========================================================================
    // Honeypot convenience method
    // =========================================================================

    /**
     * Logs an interaction captured by the honeypot trap endpoint.
     *
     * <p>Any access to a honeypot endpoint is inherently suspicious — no
     * legitimate user or automated client should ever reach it. Recorded with
     * severity {@code "CRITICAL"} to ensure immediate visibility on the
     * security dashboard.
     *
     * <p>The username parameter may be {@code "UNKNOWN"} for probes that do not
     * submit credentials, or the attempted username for login-type honeypots.
     *
     * @param ip       the source IP address that triggered the honeypot
     * @param username the username submitted to the honeypot, or {@code "UNKNOWN"}
     *                 if no credentials were provided
     */
    public void logHoneypotCapture(String ip, String username) {
        logEvent(
                "HONEYPOT_CAPTURE",
                ip,
                "HONEYPOT",
                "CRITICAL",
                username,
                "Honeypot triggered! Attacker IP: " + ip + " attempted login as: " + username,
                "CYBERSHIELD-SERVER"
        );
    }
}
