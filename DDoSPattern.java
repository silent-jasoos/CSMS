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
 * {@link AttackPattern} implementation that detects Distributed Denial-of-Service
 * (DDoS) / volumetric flood attacks by counting the number of requests received
 * from each source IP within a one-second sliding window.
 *
 * <h2>Detection algorithm</h2>
 * <p>A {@link ConcurrentHashMap} maps each source IP to a list of
 * {@link LocalDateTime} request timestamps. On every event:
 * <ol>
 *   <li>The current timestamp is appended to the IP's list.</li>
 *   <li>Entries older than one second are pruned (sliding window).</li>
 *   <li>If the remaining count reaches {@value #REQUEST_THRESHOLD}, a
 *       {@code DDOS_ATTACK} alert is persisted and logged.</li>
 * </ol>
 *
 * <h2>Why a one-second window?</h2>
 * <p>Legitimate human users and well-behaved automated clients rarely exceed
 * a handful of requests per second from a single IP. Volumetric DDoS tools
 * (e.g. LOIC, hping3) can issue thousands of packets per second. A 100 r/s
 * threshold per IP is aggressive enough to catch floods while tolerating API
 * clients that batch requests (e.g. mobile apps with prefetch).
 *
 * <h2>Limitations</h2>
 * <p>This detector operates on a <em>per-IP</em> basis. A distributed attack
 * using thousands of bot IPs (each well below the threshold) will not be
 * caught here. Complement this pattern with aggregate rate-limiting (e.g.
 * at the load-balancer layer) and IP-reputation checks.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     AttackPattern
 */
@Component
public class DDoSPattern implements AttackPattern {

    private static final Logger logger = LoggerFactory.getLogger(DDoSPattern.class);

    /** Requests per second from a single IP that triggers the DDoS alert. */
    private static final int  REQUEST_THRESHOLD = 100;

    /** Width of the sliding detection window in seconds. */
    private static final long WINDOW_SECONDS    = 1;

    /**
     * Per-IP registry of recent request timestamps.
     *
     * <p>Key: source IP address string.<br>
     * Value: mutable list of {@link LocalDateTime} request timestamps within
     * the current one-second window. Entries outside the window are pruned on
     * each incoming request from the same IP.
     */
    private final ConcurrentHashMap<String, List<LocalDateTime>> requestsPerIP =
            new ConcurrentHashMap<>();

    /** Repository used to persist {@link Alert} entities on detection. */
    private final AlertRepository alertRepository;

    /** Central logger for IDS alert events. */
    private final AttackLogger attackLogger;

    /**
     * Constructs a {@code DDoSPattern} with its required dependencies.
     *
     * @param alertRepository repository for persisting DDoS alerts
     * @param attackLogger    central logger for IDS alert events
     */
    public DDoSPattern(AlertRepository alertRepository, AttackLogger attackLogger) {
        this.alertRepository = alertRepository;
        this.attackLogger    = attackLogger;
    }

    // =========================================================================
    // AttackPattern contract
    // =========================================================================

    /**
     * Evaluates a network request event for volumetric DDoS activity.
     *
     * <p>Expected keys in {@code eventData}:
     * <ul>
     *   <li>{@code "sourceIP"} ({@link String}) – originating IP address</li>
     * </ul>
     * All other keys are ignored; this detector is purely volume-based and
     * does not inspect request content.
     *
     * <p>If {@code "sourceIP"} is absent or blank the method returns
     * {@code false} without side effects.
     *
     * <p>Note: the method will raise at most one alert per detection cycle.
     * Once the threshold is crossed the alert is saved and {@code true} is
     * returned. On the <em>very next</em> call from the same IP, the window
     * will still contain 100+ entries (they are not cleared after alerting),
     * so alerts will continue to fire on every subsequent request until the
     * window drains. This is intentional — a sustained DDoS produces
     * repeated alerts, giving the operations team continuous signal to act on.
     * If single-alert-per-burst behaviour is preferred, clear the IP's list
     * after raising the alert.
     *
     * @param eventData map describing the network request event
     * @return {@code true} if the per-second request threshold was reached and
     *         a {@code CRITICAL} alert was raised; {@code false} otherwise
     */
    @Override
    public boolean detect(Map<String, Object> eventData) {

        String ip = (String) eventData.get("sourceIP");
        if (ip == null || ip.isBlank()) {
            return false;
        }

        // Step 1 – append the current request timestamp
        List<LocalDateTime> requests =
                requestsPerIP.computeIfAbsent(ip, k -> new ArrayList<>());

        requests.add(LocalDateTime.now());

        // Step 2 – prune entries outside the one-second window
        LocalDateTime windowStart = LocalDateTime.now().minusSeconds(WINDOW_SECONDS);
        Iterator<LocalDateTime> iterator = requests.iterator();
        while (iterator.hasNext()) {
            if (iterator.next().isBefore(windowStart)) {
                iterator.remove();
            }
        }

        int requestCount = requests.size();
        logger.debug("DDoS window for IP {}: {} request(s) in last {}s",
                ip, requestCount, WINDOW_SECONDS);

        // Step 3 – threshold check
        if (requestCount >= REQUEST_THRESHOLD) {

            String description = "DDoS flood detected: " + requestCount
                    + " requests in " + WINDOW_SECONDS
                    + " second(s) from IP: " + ip;

            Alert alert = new Alert();
            alert.setAlertType("DDOS_ATTACK");
            alert.setSourceIP(ip);
            alert.setSeverity("CRITICAL");
            alert.setDescription(description);
            alert.setTimestamp(LocalDateTime.now());
            alert.setIsResolved(false);
            alertRepository.save(alert);

            attackLogger.logIDSAlert("DDOS_ATTACK", ip, "CRITICAL");

            logger.warn("DDOS_ATTACK alert raised for IP {} — {} req/s", ip, requestCount);

            return true;
        }

        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "DDoS Attack Detection"}
     */
    @Override
    public String getPatternName() {
        return "DDoS Attack Detection";
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "CRITICAL"} — a successful DDoS flood can render the
     *         application entirely unavailable to legitimate users
     */
    @Override
    public String getSeverity() {
        return "CRITICAL";
    }

    /**
     * {@inheritDoc}
     *
     * @return description of the per-second request rate threshold
     */
    @Override
    public String getDescription() {
        return "Detects volumetric flood attacks: flags any source IP "
                + "sending 100 or more requests within a single second";
    }
}
