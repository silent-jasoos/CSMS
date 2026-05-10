package com.cybershield.service;

import com.cybershield.model.Alert;
import com.cybershield.pattern.AttackPattern;
import com.cybershield.repository.AlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Intrusion Detection System (IDS) scanner service that orchestrates all
 * registered {@link AttackPattern} implementations to analyse security events
 * and simulate attack scenarios for testing and demonstration.
 *
 * <p><b>STRATEGY PATTERN:</b> The {@code patterns} list holds all
 * {@link AttackPattern} implementations registered as Spring
 * {@code @Component} beans. We call {@code detect()} on each without knowing
 * which concrete class it is — <b>Polymorphism in action</b>. Adding a new
 * attack detector requires only creating a new {@code @Component} class that
 * implements {@link AttackPattern}; this scanner picks it up automatically
 * via Spring's dependency injection, with zero modification to this class.
 *
 * <h2>How Spring injects {@code List<AttackPattern>}</h2>
 * <p>When Spring sees a constructor parameter of type
 * {@code List<AttackPattern>}, it automatically collects <em>all</em> beans
 * in the application context that implement {@link AttackPattern} and injects
 * them as an ordered list. The order follows the {@code @Order} annotation or
 * {@code Ordered} interface if present; otherwise it is unspecified.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     AttackPattern
 */
@Service
public class IDSScanner {

    private static final Logger logger = LoggerFactory.getLogger(IDSScanner.class);

    /**
     * All registered attack-detection strategy implementations, auto-injected
     * by Spring from the application context.
     *
     * <p><b>STRATEGY PATTERN:</b> {@code patterns} holds all
     * {@link AttackPattern} implementations. We call {@code detect()} on each
     * without knowing which concrete class it is — Polymorphism in action.
     */
    private final List<AttackPattern> patterns;

    /** Repository used to query persisted alerts for dashboard and API endpoints. */
    private final AlertRepository alertRepository;

    /** Central security event logger. */
    private final AttackLogger attackLogger;

    /**
     * Constructs an {@code IDSScanner} with all required dependencies.
     *
     * <p>Spring injects every {@link AttackPattern} {@code @Component} bean
     * into the {@code patterns} list automatically, including future
     * implementations added to the package.
     *
     * @param patterns        all registered {@link AttackPattern} strategy beans;
     *                        injected by Spring's collection injection mechanism
     * @param alertRepository repository for querying persisted alerts
     * @param attackLogger    central security event logger
     */
    public IDSScanner(List<AttackPattern> patterns,
                      AlertRepository alertRepository,
                      AttackLogger attackLogger) {
        this.patterns         = patterns;
        this.alertRepository  = alertRepository;
        this.attackLogger     = attackLogger;

        logger.info("IDSScanner initialised with {} pattern(s): {}",
                patterns.size(),
                patterns.stream().map(AttackPattern::getPatternName).toList());
    }

    // =========================================================================
    // Core analysis
    // =========================================================================

    /**
     * Passes a security event through every registered {@link AttackPattern}
     * and collects the results of all patterns that fired.
     *
     * <p>The polymorphic dispatch loop is the heart of the Strategy Pattern
     * implementation: the same {@code detect(eventData)} call produces
     * different behaviour depending on the runtime type of each
     * {@code AttackPattern} element. The scanner itself requires no
     * modification when new patterns are added.
     *
     * <p>All patterns are always evaluated — the loop does not short-circuit
     * on the first match. This means a single event can trigger multiple
     * patterns simultaneously (e.g. a request carrying both an SQL injection
     * payload and originating from a port-scanning IP).
     *
     * @param eventData a map of key-value pairs describing the security event;
     *                  common keys include {@code "eventType"}, {@code "sourceIP"},
     *                  {@code "port"}, and {@code "inputData"}
     * @return a (possibly empty) list of detection result maps, one per fired
     *         pattern. Each map contains:
     *         <ul>
     *           <li>{@code "patternName"} – the pattern that fired</li>
     *           <li>{@code "severity"} – the severity level of the detection</li>
     *         </ul>
     */
    public List<Map<String, Object>> analyze(Map<String, Object> eventData) {

        List<Map<String, Object>> detections = new ArrayList<>();

        for (AttackPattern pattern : patterns) {
            try {
                if (pattern.detect(eventData)) {
                    Map<String, Object> detection = new HashMap<>();
                    detection.put("patternName", pattern.getPatternName());
                    detection.put("severity",    pattern.getSeverity());
                    detections.add(detection);

                    logger.info("IDS detection: pattern='{}' severity='{}' event={}",
                            pattern.getPatternName(), pattern.getSeverity(), eventData);
                }
            } catch (Exception e) {
                // Isolate pattern failures — one broken pattern must not prevent
                // the remaining patterns from running
                logger.error("Pattern '{}' threw an exception during detection: {}",
                        pattern.getPatternName(), e.getMessage(), e);
            }
        }

        return detections;
    }

    // =========================================================================
    // Attack simulation
    // =========================================================================

    /**
     * Simulates a named attack scenario against a given source IP by
     * constructing synthetic event data and feeding it through {@link #analyze}.
     *
     * <p>This method is intended for:
     * <ul>
     *   <li><b>Integration testing</b> – verifying that detection pipelines
     *       produce alerts end-to-end without requiring real network traffic.</li>
     *   <li><b>Demo / onboarding</b> – populating the dashboard with realistic
     *       alerts during stakeholder demonstrations.</li>
     *   <li><b>Threshold validation</b> – confirming that pattern thresholds
     *       produce alerts exactly at the configured limits.</li>
     * </ul>
     *
     * <h3>Simulation behaviour per attack type</h3>
     * <table border="1" cellpadding="4">
     *   <tr><th>attackType</th><th>Synthetic events generated</th></tr>
     *   <tr><td>{@code BRUTE_FORCE}</td>
     *       <td>5 × {@code LOGIN_FAIL} events from the given IP, enough to
     *           cross the brute-force threshold of 5 failures / 2 minutes.</td></tr>
     *   <tr><td>{@code SQL_INJECTION}</td>
     *       <td>1 event with a classic multi-statement injection payload in
     *           {@code inputData}: {@code SELECT * FROM users WHERE 1=1; DROP TABLE users;--}</td></tr>
     *   <tr><td>{@code PORT_SCAN}</td>
     *       <td>15 events, each targeting a different port (1–15) from the
     *           given IP, crossing the 10-port / 30-second threshold.</td></tr>
     *   <tr><td>{@code DDOS}</td>
     *       <td>110 rapid {@code HTTP_REQUEST} events from the given IP,
     *           crossing the 100 requests / 1-second threshold.</td></tr>
     * </table>
     *
     * @param attackType the type of attack to simulate; one of
     *                   {@code "BRUTE_FORCE"}, {@code "SQL_INJECTION"},
     *                   {@code "PORT_SCAN"}, or {@code "DDOS"}
     * @param sourceIP   the synthetic source IP address to attribute the
     *                   simulated attack to
     */
    public void simulateAttack(String attackType, String sourceIP) {

        logger.info("Simulating attack: type='{}' sourceIP='{}'", attackType, sourceIP);

        switch (attackType.toUpperCase()) {

            case "BRUTE_FORCE" -> {
                // Feed 5 LOGIN_FAIL events to cross the brute-force threshold
                for (int i = 0; i < 5; i++) {
                    Map<String, Object> eventData = new HashMap<>();
                    eventData.put("eventType", "LOGIN_FAIL");
                    eventData.put("sourceIP",  sourceIP);
                    analyze(eventData);
                }
            }

            case "SQL_INJECTION" -> {
                Map<String, Object> eventData = new HashMap<>();
                eventData.put("inputData", "SELECT * FROM users WHERE 1=1; DROP TABLE users;--");
                eventData.put("sourceIP",  sourceIP);
                analyze(eventData);
            }

            case "PORT_SCAN" -> {
                // Access ports 1–15 to cross the 10-port threshold
                for (int port = 1; port <= 15; port++) {
                    Map<String, Object> eventData = new HashMap<>();
                    eventData.put("sourceIP", sourceIP);
                    eventData.put("port",     port);
                    analyze(eventData);
                }
            }

            case "DDOS" -> {
                // Send 110 rapid requests to cross the 100 req/s threshold
                for (int i = 0; i < 110; i++) {
                    Map<String, Object> eventData = new HashMap<>();
                    eventData.put("sourceIP",  sourceIP);
                    eventData.put("eventType", "HTTP_REQUEST");
                    analyze(eventData);
                }
            }

            default ->
                logger.warn("simulateAttack called with unknown attackType: '{}'", attackType);
        }
    }

    // =========================================================================
    // Alert query methods
    // =========================================================================

    /**
     * Returns all unresolved (active) alerts currently recorded in the system.
     *
     * <p>An alert is considered active ({@code isResolved = false}) from the
     * moment it is created by a pattern until an analyst or automated response
     * system marks it resolved. This method is called by the dashboard API to
     * populate the "Active Threats" panel.
     *
     * @return a list of {@link Alert} entities where {@code isResolved} is
     *         {@code false}; may be empty but never {@code null}
     */
    public List<Alert> getActiveAlerts() {
        return alertRepository.findByIsResolvedFalse();
    }

    /**
     * Returns the total count of currently unresolved alerts.
     *
     * <p>Used by the dashboard summary widget and the health-check endpoint
     * to provide a quick numeric indicator of the current threat level without
     * loading full alert entities. A count of zero means the system has no
     * outstanding unresolved threats.
     *
     * @return the number of {@link Alert} records where {@code isResolved} is
     *         {@code false}; {@code 0} if the system is clean
     */
    public long getActiveThreatCount() {
        return alertRepository.countByIsResolvedFalse();
    }
}
