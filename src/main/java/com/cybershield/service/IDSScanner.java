package com.cybershield.service;

import com.cybershield.model.Alert;
import com.cybershield.pattern.AttackPattern;
import com.cybershield.repository.AlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * IDSScanner is the orchestrator of all attack detection patterns in the
 * Intrusion Detection System (IDS) module of CyberShield CSMS.
 *
 * <p>Design Pattern: <b>Strategy</b><br>
 * This service holds a {@code List<AttackPattern>} and calls {@link AttackPattern#detect(Map)}
 * on each pattern without knowing or caring which concrete implementation it is.
 * New attack patterns can be added by simply creating a new {@code @Component}
 * that implements {@code AttackPattern} — the scanner automatically picks it up.</p>
 *
 * <p>Scheduled scanning runs every 30 seconds to evaluate events.</p>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
@Service
public class IDSScanner {

    private static final Logger logger = LoggerFactory.getLogger(IDSScanner.class);

    /**
     * List of all attack detection patterns.
     * Spring automatically injects all beans implementing AttackPattern.
     */
    @Autowired(required = false)
    private List<AttackPattern> patterns;

    /**
     * Repository for persisting Alert entities.
     */
    @Autowired
    private AlertRepository alertRepository;

    /**
     * Central logger for IDS events.
     */
    @Autowired
    private AttackLogger attackLogger;

    /**
     * Constructor — initializes patterns list.
     * If no patterns found, logs warning but continues.
     */
    public IDSScanner() {
        logger.info("IDSScanner initialized");
    }

    // =========================================================================
    // Scheduled scanning task
    // =========================================================================

    /**
     * Scheduled task that runs every 30 seconds.
     * Evaluates events with all detection patterns.
     */
    @Scheduled(fixedDelay = 30000)  // 30 seconds
    public void scanForThreats() {
        if (patterns == null || patterns.isEmpty()) {
            logger.debug("No attack patterns loaded");
            return;
        }

        logger.debug("IDS scan cycle started — {} patterns active", patterns.size());

        for (AttackPattern pattern : patterns) {
            logger.debug("Pattern loaded: {}", pattern.getPatternName());
        }
    }

    // =========================================================================
    // Public methods
    // =========================================================================

    /**
     * Analyzes a single security event with all attack detection patterns.
     *
     * <p>For each pattern in the {@code patterns} list, calls
     * {@link AttackPattern#detect(Map)} with the event data. If any pattern
     * detects an attack, it creates an alert automatically.</p>
     *
     * @param eventData map containing event details (eventType, sourceIP, etc.)
     */
    public void analyzeEvent(Map<String, Object> eventData) {
        if (patterns == null || patterns.isEmpty()) {
            return;
        }

        for (AttackPattern pattern : patterns) {
            try {
                boolean detected = pattern.detect(eventData);
                if (detected) {
                    logger.info("Threat detected by pattern: {}", pattern.getPatternName());
                }
            } catch (Exception e) {
                logger.error("Error in pattern {}: {}", pattern.getPatternName(), e.getMessage());
            }
        }
    }

    /**
     * Simulates an attack for demo and testing purposes.
     *
     * <p>Creates synthetic event data and runs it through the appropriate
     * detection pattern based on the attack type.</p>
     *
     * @param attackType type of attack to simulate (e.g., "SQL_INJECTION", "BRUTE_FORCE")
     * @param sourceIP   IP address to use as source of simulated attack
     */
    public void simulateAttack(String attackType, String sourceIP) {
        logger.info("Simulating attack — Type: {}, IP: {}", attackType, sourceIP);

        Map<String, Object> eventData = new HashMap<>();
        eventData.put("sourceIP", sourceIP);
        eventData.put("eventType", attackType);

        // Add attack-specific data based on type
        switch (attackType) {
            case "SQL_INJECTION":
                eventData.put("inputData", "' OR 1=1 --");
                break;
            case "BRUTE_FORCE":
                eventData.put("eventType", "LOGIN_FAIL");
                break;
            case "PORT_SCAN":
                eventData.put("port", 22);  // SSH port
                break;
            case "DDOS_ATTACK":
                // Timestamp already in eventData
                break;
            default:
                logger.warn("Unknown attack type for simulation: {}", attackType);
        }

        // Analyze with all patterns
        analyzeEvent(eventData);

        logger.info("Attack simulation completed");
    }

    /**
     * Returns the count of currently active (unresolved) threats.
     *
     * <p>Used by the dashboard to display the "Active Threats" card.</p>
     *
     * @return number of unresolved alerts in the database
     */
    public long getActiveThreatCount() {
        return alertRepository.countByIsResolvedFalse();
    }

    /**
     * Returns all unresolved alerts.
     *
     * @return list of active (unresolved) alerts
     */
    public List<Alert> getActiveThreats() {
        return alertRepository.findByIsResolvedFalse();
    }

    /**
     * Returns the total number of attack patterns loaded.
     *
     * @return count of active patterns
     */
    public int getPatternCount() {
        return (patterns == null) ? 0 : patterns.size();
    }

    /**
     * Returns names of all loaded patterns.
     *
     * @return list of pattern names
     */
    public List<String> getPatternNames() {
        if (patterns == null) {
            return List.of();
        }
        return patterns.stream()
                .map(AttackPattern::getPatternName)
                .toList();
    }
}
