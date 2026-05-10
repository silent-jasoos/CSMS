package com.cybershield.pattern;

import com.cybershield.model.Alert;
import com.cybershield.repository.AlertRepository;
import com.cybershield.service.AttackLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * {@link AttackPattern} implementation that detects SQL injection and
 * cross-site scripting (XSS) payloads in user-supplied input data by
 * scanning for known malicious keywords and syntax patterns.
 *
 * <h2>Detection algorithm</h2>
 * <p>The method reads the {@code "inputData"} value from the event map,
 * converts it to upper-case for case-insensitive comparison, and checks
 * whether it contains any entry from the {@link #SQL_KEYWORDS} list.
 * A single keyword match is sufficient to raise a {@code CRITICAL} alert —
 * injection attacks do not require volume; a single crafted request can
 * exfiltrate an entire database or destroy schema objects.
 *
 * <h2>Keyword selection rationale</h2>
 * <ul>
 *   <li>{@code SELECT}, {@code INSERT}, {@code UPDATE}, {@code DELETE},
 *       {@code DROP} — core DML/DDL verbs present in every SQL injection payload.</li>
 *   <li>{@code --}, {@code ;} — comment and statement-termination characters
 *       used to truncate the intended query and append attacker-controlled SQL.</li>
 *   <li>{@code UNION} — enables data exfiltration by appending a second
 *       {@code SELECT} that returns data from other tables.</li>
 *   <li>{@code OR 1=1} — classic tautology that bypasses {@code WHERE} clauses
 *       in authentication queries.</li>
 *   <li>{@code <script>} — XSS payload marker; included here because many
 *       injection vectors accept HTML as well as SQL.</li>
 *   <li>{@code EXEC} — SQL Server stored-procedure execution, used to run
 *       arbitrary OS commands via {@code xp_cmdshell}.</li>
 * </ul>
 *
 * <h2>Limitations</h2>
 * <p>Keyword matching is a first-pass heuristic. Sophisticated attackers use
 * encoding (URL, hex, Unicode) to bypass naive keyword lists. This detector
 * should be complemented by a dedicated WAF and prepared-statement enforcement
 * at the persistence layer.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     AttackPattern
 */
@Component
public class SQLInjectionPattern implements AttackPattern {

    private static final Logger logger = LoggerFactory.getLogger(SQLInjectionPattern.class);

    /**
     * Ordered list of SQL and XSS keywords/tokens that indicate an injection
     * attempt. The list is checked case-insensitively against the input string.
     *
     * <p>Multi-word patterns such as {@code "OR 1=1"} are checked as substrings,
     * so they also catch variants embedded in larger expressions (e.g.
     * {@code "' OR 1=1 --"}).
     */
    private static final List<String> SQL_KEYWORDS = List.of(
            "SELECT", "DROP", "INSERT", "UPDATE", "DELETE",
            "--", ";", "UNION", "OR 1=1", "<script>", "EXEC"
    );

    /** Repository used to persist {@link Alert} entities on detection. */
    private final AlertRepository alertRepository;

    /** Central logger for IDS alert events. */
    private final AttackLogger attackLogger;

    /**
     * Constructs a {@code SQLInjectionPattern} with its required dependencies.
     *
     * @param alertRepository repository for persisting SQL-injection alerts
     * @param attackLogger    central logger for IDS alert events
     */
    public SQLInjectionPattern(AlertRepository alertRepository, AttackLogger attackLogger) {
        this.alertRepository = alertRepository;
        this.attackLogger    = attackLogger;
    }

    // =========================================================================
    // AttackPattern contract
    // =========================================================================

    /**
     * Scans the {@code "inputData"} field of the event for SQL injection or
     * XSS keyword patterns.
     *
     * <p>Expected keys in {@code eventData}:
     * <ul>
     *   <li>{@code "inputData"} ({@link String}) – the raw user input to
     *       analyse (e.g. a form field value, URL parameter, or JSON body
     *       fragment)</li>
     *   <li>{@code "sourceIP"} ({@link String}) – the originating IP address,
     *       recorded in the alert for attribution</li>
     * </ul>
     *
     * <p>If {@code "inputData"} is absent or not a non-empty {@link String},
     * the method returns {@code false} immediately.
     *
     * <p>Because a single injection attempt is sufficient to cause data
     * exfiltration or schema destruction, the severity is immediately
     * {@code "CRITICAL"} — unlike brute-force detection there is no threshold
     * to accumulate.
     *
     * @param eventData map describing the request or input event
     * @return {@code true} if an injection keyword was found and a
     *         {@code CRITICAL} alert was raised; {@code false} otherwise
     */
    @Override
    public boolean detect(Map<String, Object> eventData) {

        Object inputObj = eventData.get("inputData");
        if (!(inputObj instanceof String inputData) || inputData.isBlank()) {
            return false;
        }

        String ip           = (String) eventData.getOrDefault("sourceIP", "UNKNOWN");
        String inputUpper   = inputData.toUpperCase();

        for (String keyword : SQL_KEYWORDS) {
            if (inputUpper.contains(keyword.toUpperCase())) {

                String description = "SQL/XSS injection detected — keyword '"
                        + keyword + "' found in input from IP: " + ip
                        + " | Input snippet: "
                        + inputData.substring(0, Math.min(inputData.length(), 120));

                Alert alert = new Alert();
                alert.setAlertType("SQL_INJECTION");
                alert.setSourceIP(ip);
                alert.setSeverity("CRITICAL");
                alert.setDescription(description);
                alert.setTimestamp(LocalDateTime.now());
                alert.setIsResolved(false);
                alertRepository.save(alert);

                attackLogger.logIDSAlert("SQL_INJECTION", ip, "CRITICAL");

                logger.warn("SQL_INJECTION alert raised — keyword '{}' from IP {}",
                        keyword, ip);

                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "SQL Injection Detection"}
     */
    @Override
    public String getPatternName() {
        return "SQL Injection Detection";
    }

    /**
     * {@inheritDoc}
     *
     * @return {@code "CRITICAL"} — a successful injection can exfiltrate,
     *         modify, or destroy the entire database in a single request
     */
    @Override
    public String getSeverity() {
        return "CRITICAL";
    }

    /**
     * {@inheritDoc}
     *
     * @return description of the keyword-matching strategy and covered attack vectors
     */
    @Override
    public String getDescription() {
        return "Detects SQL injection and XSS payloads by scanning input for "
                + "malicious keywords: SELECT, DROP, UNION, OR 1=1, <script>, EXEC, and more";
    }
}
