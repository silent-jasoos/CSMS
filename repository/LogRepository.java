package com.cybershield.repository;

import com.cybershield.model.LogEntry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Spring Data JPA repository for the {@code log_entries} table.
 *
 * <p>Log entries are the highest-volume table in CyberShield — thousands of
 * records accumulate quickly.  Most query methods therefore accept a
 * {@link Pageable} parameter so the UI can paginate results instead of
 * loading the entire table at once.</p>
 *
 * <p>Spring generates all SQL automatically from method names.</p>
 */
@Repository
public interface LogRepository extends JpaRepository<LogEntry, Long> {

    /**
     * Returns a paginated list of log entries filtered by event type.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries WHERE event_type = ? LIMIT ? OFFSET ?}</p>
     * <p>Called when an analyst filters the log table by a specific event type
     * (e.g. LOGIN_FAIL, FIREWALL_BLOCK, IDS_ALERT).</p>
     *
     * @param eventType the event type string to filter by
     * @param pageable  page number, page size, and optional sort from the UI request
     * @return one page of matching log entries
     */
    Page<LogEntry> findByEventType(String eventType, Pageable pageable);

    /**
     * Returns a paginated list of log entries filtered by severity level.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries WHERE severity = ? LIMIT ? OFFSET ?}</p>
     * <p>Called when the dashboard displays only CRITICAL or HIGH events.</p>
     *
     * @param severity the severity string (LOW, MEDIUM, HIGH, CRITICAL)
     * @param pageable pagination and sort parameters
     * @return one page of matching log entries
     */
    Page<LogEntry> findBySeverity(String severity, Pageable pageable);

    /**
     * Returns a paginated list of log entries that originated from a given source IP.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries WHERE source_ip = ? LIMIT ? OFFSET ?}</p>
     * <p>Used by analysts to investigate all activity from a specific IP address.</p>
     *
     * @param sourceIP the source IP address to filter by
     * @param pageable pagination and sort parameters
     * @return one page of matching log entries
     */
    Page<LogEntry> findBySourceIP(String sourceIP, Pageable pageable);

    /**
     * Returns a paginated list of log entries associated with a specific username.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries WHERE username = ? LIMIT ? OFFSET ?}</p>
     * <p>Called when an admin reviews the complete activity history of a user account.</p>
     *
     * @param username the username to filter by
     * @param pageable pagination and sort parameters
     * @return one page of matching log entries
     */
    Page<LogEntry> findByUsername(String username, Pageable pageable);

    /**
     * Returns a paginated list of log entries whose timestamp falls within a date/time range.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries WHERE timestamp BETWEEN ? AND ? LIMIT ? OFFSET ?}</p>
     * <p>Used by the date-range filter on the audit log screen.</p>
     *
     * @param start    the start of the time window (inclusive)
     * @param end      the end of the time window (inclusive)
     * @param pageable pagination and sort parameters
     * @return one page of matching log entries
     */
    Page<LogEntry> findByTimestampBetween(LocalDateTime start, LocalDateTime end, Pageable pageable);

    /**
     * Counts events of a specific type that occurred after a given point in time.
     * <p>Generated SQL:
     * {@code SELECT COUNT(*) FROM log_entries WHERE event_type = ? AND timestamp > ?}</p>
     * <p>Used by the dashboard stats panel — for example, to count how many
     * LOGIN_FAIL events happened in the last hour and trigger rate-limit warnings.</p>
     *
     * @param eventType the event type to count
     * @param after     only count events that occurred after this timestamp
     * @return the number of matching events
     */
    long countByEventTypeAndTimestampAfter(String eventType, LocalDateTime after);

    /**
     * Counts all log entries recorded after a given point in time.
     * <p>Generated SQL:
     * {@code SELECT COUNT(*) FROM log_entries WHERE timestamp > ?}</p>
     * <p>Used by the dashboard to show total event volume for the last 24 hours.</p>
     *
     * @param after count only entries recorded after this timestamp
     * @return total number of log entries since that timestamp
     */
    long countByTimestampAfter(LocalDateTime after);

    /**
     * Retrieves the 10 most recent log entries across the entire table.
     * <p>Generated SQL:
     * {@code SELECT * FROM log_entries ORDER BY timestamp DESC LIMIT 10}</p>
     * <p>Displayed in the "Recent Activity" widget on the main dashboard.</p>
     *
     * @return the 10 latest log entries, newest first
     */
    List<LogEntry> findTop10ByOrderByTimestampDesc();
}