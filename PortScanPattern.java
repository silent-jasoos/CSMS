package com.cybershield.pattern;

import com.cybershield.model.Alert;
import com.cybershield.repository.AlertRepository;
import com.cybershield.service.AttackLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link AttackPattern} implementation that detects horizontal port-scanning
 * activity by tracking how many distinct ports each source IP has accessed
 * within a 30-second sliding window.
 *
 * <h2>Detection algorithm</h2>
 * <p>A {@link ConcurrentHashMap} maps each source IP to a nested
 * {@link Map} of {@code port → timestamp}. On every evaluated event:
 * <ol>
 *   <li>The destination port and the current {@link LocalDateTime} are
 *       recorded (or updated) for the source IP.</li>
 *   <li>All port entries whose timestamp is older than 30 seconds are evicted,
 *       implementing the sliding window.</li>
 *   <li>If the number of <em>distinct</em> ports remaining in the window
 *       reaches {@value #PORT_THRESHOLD}, a {@code PORT_SCAN} alert is raised.</li>
 * </ol>
 *
 * <h2>Why track last-seen timestamp per port?</h2>
 * <p>Storing a single {@link LocalDateTime} per port (rather than a list)
 * keeps memory usage bounded at one entry per unique (IP, port) pair within
 * the window. The trade-off is that repeated probes to the same port reset
 * its expiry timer rather than being counted multiple times — which is the
 * desired behaviour for port-scan detection (we care about breadth, not depth).
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     AttackPattern
 */
@Component
public class PortScanPattern implements AttackPattern {

    private static final Logger logger = LoggerFactory.getLogger(PortScanPattern.class);

    /** Number of distinct ports accessed within the window that triggers an alert. */
    private static final int  PORT_THRESHOLD  = 10;

    /** Width of the sliding detection window in seconds. */
    private static final long WINDOW_SECONDS  = 30;

    /**
     * Per-IP registry mapping each recently accessed port to the timestamp of
     * its most recent access.
     *
     * <p>Outer key: source IP address string.<br>
     * Inner key: destination port number ({@link Integer}).<br>
     * Inner value: {@link LocalDateTime} of the most recent probe to that port
     * from the outer IP, used for sliding-window eviction.
     */
    private final ConcurrentHashMap<String, Map<Integer, LocalDateTime>> portAccessMap =
            new ConcurrentHashMap<>();

    /** Repository used to persist {@link Alert} entities on detection. */
    private final AlertRepository alertRepository;

    /** Central logger for IDS alert events. */
    private final AttackLogger attackLogger;

    /**
     * Constructs a {@code PortScanPattern} with its required dependencies.
     *
     * @param alertRepository repository for persisting port-scan alerts
     * @param attackLogger    central logger for IDS alert events
     */
    public PortScanPattern(AlertRepository alertRepository, AttackLogger attackLogger) {
        this.alertRepository = alertRepository;
        this.attackLogger    = attackLogger;
    }

    // =========================================================================
    // AttackPattern contract
    // =========================================================================

    /**
     * Evaluates a security event for port-scanning behaviour.
     *
     * <p>Expected keys in {@code eventData}:
     * <ul>
     *   <li>{@code "sourceIP"} ({@link String}) – originating IP address</li>
     *   <li>{@code "port"} ({@link Integer}) – destination port probed</li>
     * </ul>
     * If either key is absent or the port value is not an {@link Integer},
     * the method returns {@code false} without side effects.
     *
     * @param eventData map describing the network event
     * @return {@code true} if the port-scan threshold was reached and an alert
     *         was raised; {@code false} otherwise
     */
    @Override
    public boolean detect(Map<String, Object> eventData) {

        String ip = (String) eventData.get("sourceIP");
        Object portObj = eventData.get("port");

        if (ip == null || ip.isBlank() || !(portObj instanceof Integer)) {
            return false;
        }

        int port = (Integer) portObj;

        // Retrieve or create the per-IP port map
        Map<Integer, LocalDateTime> portTimestamps =
                portAccessMap.computeIfAbsent(ip, k -> new ConcurrentHashMap<>());

        // Record / refresh the timestamp for this port
        portTimestamps.put(port, LocalDateTime.now());

        // Evict ports outside the 30-second window
        LocalDateTime windowStart = LocalDateTime.now().minusSeconds(WINDOW_SECONDS);
        Iterator<Map.Entry<Integer, LocalDateTime>> it =
                portTimestamps.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue().isBefore(windowStart)) {
                it.remove();
            }
        }

        int distinctPorts = portTimestamps.size();
        logger.debug("PortScan window for IP {}: {} distinct port(s) in last {}s",
                ip, distinctPorts, WINDOW_SECONDS);

        if (distinctPorts >= PORT_THRESHOLD) {

            String description = "Port scan detected: " + distinctPorts
                    + " distinct ports accessed in " + WINDOW_SECONDS
                    + " seconds from IP: " + ip;

            Alert alert = new Alert();
            alert.setAlertType("PORT_SCAN");
            alert.setSourceIP(ip);
            alert.setSeverity("MEDIUM");
            alert.setDescription(description);
            alert.setTimestamp(LocalDateTime.now());
            alert.setIsResolved(false);
            alertRepository.save(alert);

            attackLogger.logIDSAlert("PORT_SCAN", ip, "MEDIUM");

            logger.warn("PORT_SCAN alert raised for IP {} — {} ports in {}s",
                    ip, distinctPorts, WINDOW_SECONDS);

            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "Port Scan Detection"}
     */
    @Override
    public String getPatternName() {
        return "Port Scan Detection";
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "MEDIUM"} — port scanning is reconnaissance activity,
     *         typically a precursor to a more targeted attack
     */
    @Override
    public String getSeverity() {
        return "MEDIUM";
    }

    /**
     * {@inheritDoc}
     *
     * @return description of the distinct-port threshold and time window
     */
    @Override
    public String getDescription() {
        return "Detects access to 10 or more distinct ports from the same IP within 30 seconds";
    }
}
