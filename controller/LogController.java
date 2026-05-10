package com.cybershield.controller;

import com.cybershield.model.LogEntry;
import com.cybershield.repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * LogController exposes REST endpoints for querying and exporting system log entries
 * in CyberShield CSMS.
 *
 * <p>Base path: {@code /api/logs}</p>
 *
 * <p>Supports flexible filtering by event type, severity, source IP, and username
 * with server-side pagination. Also provides a CSV export endpoint for offline analysis.</p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/logs")
@CrossOrigin
public class LogController {

    /** Repository providing query methods for {@link LogEntry} entities. */
    @Autowired
    private LogRepository logRepository;

    // -------------------------------------------------------------------------
    // GET /api/logs/
    // -------------------------------------------------------------------------

    /**
     * Returns a paginated list of log entries, optionally filtered by one or more criteria.
     *
     * <p>Filter priority (first non-null filter wins):
     * <ol>
     *   <li>{@code eventType} – filter by event category (e.g., "LOGIN", "FIREWALL_BLOCK")</li>
     *   <li>{@code severity} – filter by severity level (e.g., "HIGH", "MEDIUM", "LOW")</li>
     *   <li>{@code sourceIP} – filter by originating IP address</li>
     *   <li>No filter – return all log entries paged</li>
     * </ol>
     * </p>
     *
     * <p>The {@code username} filter is reserved for future implementation and currently
     * falls through to an unfiltered query.</p>
     *
     * @param eventType optional filter by event type string
     * @param severity  optional filter by severity string
     * @param sourceIP  optional filter by source IP address string
     * @param username  optional filter by username (reserved, not yet implemented)
     * @param page      zero-based page index (default {@code 0})
     * @param size      number of records per page (default {@code 20})
     * @return {@link ResponseEntity} containing a {@link Page} of {@link LogEntry} objects
     */
    @GetMapping("/")
    public ResponseEntity<Page<LogEntry>> getLogs(
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String sourceIP,
            @RequestParam(required = false) String username,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());

        Page<LogEntry> result;

        if (eventType != null && !eventType.isEmpty()) {
            result = logRepository.findByEventType(eventType, pageable);
        } else if (severity != null && !severity.isEmpty()) {
            result = logRepository.findBySeverity(severity, pageable);
        } else if (sourceIP != null && !sourceIP.isEmpty()) {
            result = logRepository.findBySourceIP(sourceIP, pageable);
        } else {
            // username filter or no filter — return all paged
            result = logRepository.findAll(pageable);
        }

        return ResponseEntity.ok(result);
    }

    // -------------------------------------------------------------------------
    // GET /api/logs/export
    // -------------------------------------------------------------------------

    /**
     * Exports all log entries as a downloadable CSV file.
     *
     * <p>The response sets the {@code Content-Disposition} header to trigger a file
     * download in the browser. Columns exported:
     * {@code id, timestamp, eventType, severity, sourceIP, username, message}.</p>
     *
     * <p><strong>Warning:</strong> This fetches all records without pagination. For very
     * large datasets consider streaming or adding date-range parameters.</p>
     *
     * @return {@link ResponseEntity} with CSV bytes as the body and appropriate download headers
     */
    @GetMapping("/export")
    public ResponseEntity<byte[]> exportLogs() {
        List<LogEntry> allLogs = logRepository.findAll();

        StringBuilder csv = new StringBuilder();
        csv.append("id,timestamp,eventType,severity,sourceIP,username,message\n");

        for (LogEntry log : allLogs) {
            csv.append(csvEscape(String.valueOf(log.getId()))).append(",")
               .append(csvEscape(String.valueOf(log.getTimestamp()))).append(",")
               .append(csvEscape(log.getEventType())).append(",")
               .append(csvEscape(log.getSeverity())).append(",")
               .append(csvEscape(log.getSourceIP())).append(",")
               .append(csvEscape(log.getUsername())).append(",")
               .append(csvEscape(log.getMessage())).append("\n");
        }

        byte[] csvBytes = csv.toString().getBytes(StandardCharsets.UTF_8);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("text/csv"));
        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=logs.csv");
        headers.setContentLength(csvBytes.length);

        return ResponseEntity.ok()
                .headers(headers)
                .body(csvBytes);
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    /**
     * Escapes a single CSV field value by wrapping it in double-quotes and
     * escaping any internal double-quote characters.
     *
     * @param value the raw field value (may be {@code null})
     * @return a CSV-safe quoted string
     */
    private String csvEscape(String value) {
        if (value == null) return "\"\"";
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }
}
