package com.cybershield.pattern;

import com.cybershield.model.Alert;
import com.cybershield.repository.AlertRepository;
import com.cybershield.service.AttackLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link AttackPattern} implementation that detects brute-force login attacks
 * by tracking failed authentication attempts per source IP within a rolling
 * two-minute window.
 *
 * <h2>Detection algorithm</h2>
 * <p>A sliding-window counter is maintained per source IP address using a
 * {@link ConcurrentHashMap} that maps each IP to a chronologically ordered
 * list of {@link LocalDateTime} failure timestamps:
 * <ol>
 *   <li>On every {@code LOGIN_FAIL} event the current timestamp is appended
 *       to the IP's list.</li>
 *   <li>All entries older than two minutes are pruned from the list — this
 *       implements the <em>sliding window</em>: only recent failures count.</li>
 *   <li>If the remaining list size reaches the threshold of <b>5</b>, a
 *       {@code BRUTE_FORCE} alert is created, persisted, and logged.</li>
 * </ol>
 *
 * <h2>Thread safety</h2>
 * <p>{@link ConcurrentHashMap} provides safe concurrent access for the outer
 * map. The per-IP {@link ArrayList} is accessed inside
 * {@code computeIfAbsent}, which is atomic for key creation. The pruning and
 * size check that follow are performed on the list reference while it is still
 * held in the local scope of the calling thread; under very high concurrency
 * from the same IP this could produce a duplicate alert within the same second.
 * For production environments consider wrapping the list in a
 * {@link java.util.concurrent.CopyOnWriteArrayList} or synchronising on the
 * list instance.
 *
 * <h2>Memory management</h2>
 * <p>Entries are evicted lazily on the next failure event from the same IP.
 * IPs that stop sending failures will retain their (now-empty after window
 * expiry) lists indefinitely. A scheduled task should periodically call
 * {@code loginFailures.entrySet().removeIf(e -> e.getValue().isEmpty())}
 * to reclaim memory in long-running deployments.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     AttackPattern
 */
@Component
public class BruteForcePattern implements AttackPattern {

    private static final Logger logger = LoggerFactory.getLogger(BruteForcePattern.class);

    /** Number of failed login attempts within the time window that triggers an alert. */
    private static final int    FAILURE_THRESHOLD_COUNT   = 5;

    /** Width of the sliding detection window in minutes. */
    private static final long   WINDOW_MINUTES            = 2;

    /**
     * Per-IP registry of recent login-failure timestamps.
     *
     * <p>Key: source IP address string (e.g. {@code "192.168.1.10"}).<br>
     * Value: mutable list of {@link LocalDateTime} instants at which a
     * {@code LOGIN_FAIL} event was received from that IP, kept in insertion
     * (chronological) order. Entries outside the two-minute window are pruned
     * on each incoming failure from the same IP.
     */
    private final ConcurrentHashMap<String, List<LocalDateTime>> loginFailures =
            new ConcurrentHashMap<>();

    /**
     * Repository used to persist {@link Alert} entities when brute-force
     * activity is detected.
     */
    private final AlertRepository alertRepository;

    /**
     * Central event logger; called after an alert is persisted to record an
     * IDS alert log entry in the {@code log_entries} table.
     */
    private final AttackLogger attackLogger;

    /**
     * Constructs a {@code BruteForcePattern} with its required dependencies.
     *
     * @param alertRepository repository for persisting brute-force alerts
     * @param attackLogger    central logger for IDS alert events
     */
    public BruteForcePattern(AlertRepository alertRepository, AttackLogger attackLogger) {
        this.alertRepository = alertRepository;
        this.attackLogger    = attackLogger;
    }

    // =========================================================================
    // AttackPattern contract
    // =========================================================================

    /**
     * Evaluates a security event for brute-force login activity.
     *
     * <p>The method only acts on events whose {@code "eventType"} key equals
     * {@code "LOGIN_FAIL"}. For all other event types it returns {@code false}
     * immediately without side effects.
     *
     * <p><b>Processing steps for a {@code LOGIN_FAIL} event:</b>
     * <ol>
     *   <li>Read the {@code "sourceIP"} value from {@code eventData}.</li>
     *   <li>Append {@link LocalDateTime#now()} to the IP's failure list
     *       (creating the list atomically if absent via
     *       {@link ConcurrentHashMap#computeIfAbsent}).</li>
     *   <li>Prune all timestamps older than {@value #WINDOW_MINUTES} minutes
     *       using an {@link Iterator} to avoid
     *       {@link java.util.ConcurrentModificationException}.</li>
     *   <li>If the pruned list size is ≥ {@value #FAILURE_THRESHOLD_COUNT},
     *       create and persist a {@code BRUTE_FORCE} alert, emit an IDS log
     *       entry, and return {@code true}.</li>
     * </ol>
     *
     * @param eventData map that must contain at minimum:
     *                  {@code "eventType"} ({@link String}) and
     *                  {@code "sourceIP"} ({@link String})
     * @return {@code true} if the brute-force threshold was reached and an
     *         alert was raised; {@code false} otherwise
     */
    @Override
    public boolean detect(Map<String, Object> eventData) {

        Object eventType = eventData.get("eventType");
        if (!"LOGIN_FAIL".equals(eventType)) {
            return false;
        }

        String ip = (String) eventData.get("sourceIP");
        if (ip == null || ip.isBlank()) {
            logger.warn("BruteForcePattern received LOGIN_FAIL event with no sourceIP");
            return false;
        }

        // Step 1 – append the current failure timestamp
        List<LocalDateTime> failures =
                loginFailures.computeIfAbsent(ip, k -> new ArrayList<>());

        failures.add(LocalDateTime.now());

        // Step 2 – prune entries outside the sliding window
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(WINDOW_MINUTES);
        Iterator<LocalDateTime> iterator = failures.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().isBefore(windowStart)) {
                iterator.remove();
            }
        }

        logger.debug("BruteForce window for IP {}: {} failure(s) in last {} min",
                ip, failures.size(), WINDOW_MINUTES);

        // Step 3 – threshold check
        if (failures.size() >= FAILURE_THRESHOLD_COUNT) {

            String description = FAILURE_THRESHOLD_COUNT + "+ login failures in "
                    + WINDOW_MINUTES + " minutes from IP: " + ip;

            Alert alert = new Alert();
            alert.setAlertType("BRUTE_FORCE");
            alert.setSourceIP(ip);
            alert.setSeverity("HIGH");
            alert.setDescription(description);
            alert.setTimestamp(LocalDateTime.now());
            alert.setIsResolved(false);
            alertRepository.save(alert);

            attackLogger.logIDSAlert("BRUTE_FORCE", ip, "HIGH");

            logger.warn("BRUTE_FORCE alert raised for IP {} — {} failures detected",
                    ip, failures.size());

            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "Brute Force Detection"}
     */
    @Override
    public String getPatternName() {
        return "Brute Force Detection";
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "HIGH"} — repeated authentication failures indicate a
     *         targeted credential-stuffing or password-spray campaign
     */
    @Override
    public String getSeverity() {
        return "HIGH";
    }

    /**
     * {@inheritDoc}
     *
     * @return a description of the detection threshold and time window
     */
    @Override
    public String getDescription() {
        return "Detects 5 or more failed login attempts from same IP within 2 minutes";
    }
}
