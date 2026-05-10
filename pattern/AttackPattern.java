package com.cybershield.pattern;

import java.util.Map;

/**
 * Strategy Pattern interface for CyberShield attack detection algorithms.
 *
 * <p><b>Design pattern — Strategy:</b> this interface defines the contract
 * that every attack-detection algorithm must fulfil. Each concrete
 * implementation ({@code BruteForcePattern}, {@code PortScanPattern},
 * {@code SQLInjectionPattern}, {@code DDoSPattern}) encapsulates a
 * self-contained detection algorithm. The consuming class —
 * {@code IDSScanner} — holds a {@code List<AttackPattern>} and calls
 * {@link #detect(Map)} on every element <em>without knowing or caring</em>
 * which concrete class it is invoking. This is <b>polymorphism in action</b>:
 * the same method call produces different behaviour depending on the runtime
 * type of the object.
 *
 * <p><b>Why an interface and not an abstract class?</b> Each detection
 * algorithm has no shared state or shared behaviour — only a shared contract.
 * An interface communicates exactly that. It also allows each implementation
 * to extend a different class if needed (e.g. a Spring-managed
 * {@code @Component} that must extend a framework base class).
 *
 * <p><b>Open/Closed Principle:</b> new attack patterns can be added by simply
 * creating a new {@code @Component} that implements this interface. The
 * {@code IDSScanner} requires zero modification — Spring auto-injects the
 * new bean into its {@code List<AttackPattern>} automatically.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
public interface AttackPattern {

    /**
     * Analyses a single security event and determines whether this pattern's
     * attack signature is present.
     *
     * <p>Implementations receive a generic {@code Map<String, Object>} rather
     * than a typed event class so that the interface remains decoupled from any
     * specific event model. Common keys include:
     * <ul>
     *   <li>{@code "eventType"} – e.g. {@code "LOGIN_FAIL"}, {@code "HTTP_REQUEST"}</li>
     *   <li>{@code "sourceIP"} – the originating IP address as a {@link String}</li>
     *   <li>{@code "port"} – destination port as an {@link Integer}</li>
     *   <li>{@code "inputData"} – raw user input for injection analysis</li>
     * </ul>
     *
     * <p>Implementations are expected to maintain their own internal state
     * (e.g. per-IP counters, sliding-window timestamps) using thread-safe
     * data structures such as {@link java.util.concurrent.ConcurrentHashMap}.
     *
     * @param eventData a map of key-value pairs describing the security event
     *                  to be analysed; must not be {@code null}
     * @return {@code true} if the attack pattern was detected and an alert has
     *         been persisted; {@code false} otherwise
     */
    boolean detect(Map<String, Object> eventData);

    /**
     * Returns the human-readable name of this detection pattern.
     *
     * <p>Used by {@code IDSScanner} to populate the {@code patternName} field
     * in detection result maps and in log messages.
     *
     * @return a short, descriptive name such as {@code "Brute Force Detection"}
     */
    String getPatternName();

    /**
     * Returns the default severity level produced by this pattern when an
     * attack is detected.
     *
     * <p>Severity levels used across CyberShield:
     * <ul>
     *   <li>{@code "LOW"} – informational; no immediate action required</li>
     *   <li>{@code "MEDIUM"} – suspicious activity warranting investigation</li>
     *   <li>{@code "HIGH"} – confirmed attack with significant risk</li>
     *   <li>{@code "CRITICAL"} – active, severe threat requiring immediate response</li>
     * </ul>
     *
     * @return one of {@code "LOW"}, {@code "MEDIUM"}, {@code "HIGH"}, or
     *         {@code "CRITICAL"}
     */
    String getSeverity();

    /**
     * Returns a human-readable description of what this pattern detects,
     * including the thresholds and time windows used by its algorithm.
     *
     * <p>Displayed in the CyberShield dashboard's "Active Detection Patterns"
     * panel and included in generated security reports.
     *
     * @return a plain-English description of the detection logic
     */
    String getDescription();
}
