package com.cybershield.repository;

import com.cybershield.model.Alert;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Spring Data JPA repository for the {@code ids_alerts} table.
 *
 * <p>IDS (Intrusion Detection System) alerts are generated when the IDS engine
 * detects suspicious behaviour such as port scans, brute-force attempts,
 * SQL injection, or DDoS traffic.  Analysts review and resolve these alerts.</p>
 *
 * <p>Spring generates all SQL automatically from method names.</p>
 */
@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {

    /**
     * Retrieves all alerts that have NOT yet been resolved by an analyst.
     * <p>Generated SQL: {@code SELECT * FROM ids_alerts WHERE is_resolved = FALSE}</p>
     * <p>This is the primary query for the "Active Alerts" panel — analysts see
     * only unresolved alerts so nothing is missed.</p>
     *
     * @return list of all unresolved IDS alerts
     */
    List<Alert> findByIsResolvedFalse();

    /**
     * Retrieves all alerts with a specific severity level.
     * <p>Generated SQL: {@code SELECT * FROM ids_alerts WHERE severity = ?}</p>
     * <p>Called when the dashboard filters alerts by severity
     * (e.g. show only CRITICAL alerts).</p>
     *
     * @param severity the severity string (LOW, MEDIUM, HIGH, CRITICAL)
     * @return list of alerts matching that severity
     */
    List<Alert> findBySeverity(String severity);

    /**
     * Counts how many alerts are currently unresolved.
     * <p>Generated SQL: {@code SELECT COUNT(*) FROM ids_alerts WHERE is_resolved = FALSE}</p>
     * <p>Used by the dashboard badge/counter that shows open alert count
     * in the navigation bar.</p>
     *
     * @return number of unresolved alerts
     */
    long countByIsResolvedFalse();

    /**
     * Retrieves all alerts of a given alert type.
     * <p>Generated SQL: {@code SELECT * FROM ids_alerts WHERE alert_type = ?}</p>
     * <p>Called when filtering alerts by category — for example, showing all
     * BRUTE_FORCE or PORT_SCAN alerts grouped together.</p>
     *
     * @param alertType the alert type string (e.g. "BRUTE_FORCE", "PORT_SCAN",
     *                  "SQL_INJECTION", "DDOS_ATTACK")
     * @return list of alerts with that type
     */
    List<Alert> findByAlertType(String alertType);

    /**
     * Retrieves all alerts detected after a given point in time.
     * <p>Generated SQL: {@code SELECT * FROM ids_alerts WHERE detected_at > ?}</p>
     * <p>Used by scheduled jobs and the dashboard to load alerts from the
     * last N hours (e.g. last 24 hours) for trend analysis.</p>
     *
     * @param after only return alerts detected after this timestamp
     * @return list of recent alerts
     */
    List<Alert> findByDetectedAtAfter(LocalDateTime after);

    /**
     * Returns a paginated view of all alerts (any status, any severity).
     * <p>Generated SQL: {@code SELECT * FROM ids_alerts LIMIT ? OFFSET ?}</p>
     * <p>Used by the full Alerts History page where analysts can scroll
     * through every alert ever recorded, with sorting support.</p>
     *
     * @param pageable page number, size, and optional sort order
     * @return one page of alert records
     */
    Page<Alert> findAll(Pageable pageable);
}