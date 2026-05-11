package com.cybershield.repository;

import com.cybershield.model.HoneypotCapture;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Spring Data JPA repository for the honeypot_captures table.
 *
 * Provides query methods for managing and analyzing honeypot trap data.
 * All methods are automatically implemented by Spring Data JPA.
 */
@Repository
public interface HoneypotCaptureRepository extends JpaRepository<HoneypotCapture, Long> {

    /**
     * Retrieve all honeypot captures.
     * Used by admin dashboard to view all attacker attempts.
     * SQL: SELECT * FROM honeypot_captures ORDER BY timestamp DESC
     */
    @Override
    List<HoneypotCapture> findAll();

    /**
     * Count honeypot captures recorded after a specific timestamp.
     * Used for dashboard "today's honeypot captures" counter.
     * SQL: SELECT COUNT(*) FROM honeypot_captures WHERE timestamp > ?
     */
    long countByTimestampAfter(LocalDateTime timestamp);

    /**
     * Retrieve honeypot captures from a specific IP address.
     * Used to analyze attack patterns from repeat attackers.
     * SQL: SELECT * FROM honeypot_captures WHERE captured_ip = ? ORDER BY timestamp DESC
     */
    List<HoneypotCapture> findByCapturedIP(String capturedIP);

    /**
     * Count honeypot captures from a specific IP.
     * SQL: SELECT COUNT(*) FROM honeypot_captures WHERE captured_ip = ?
     */
    long countByCapturedIP(String capturedIP);

    /**
     * Retrieve captures recorded on a specific day.
     * SQL: SELECT * FROM honeypot_captures WHERE DATE(timestamp) = DATE(?)
     */
    List<HoneypotCapture> findByTimestampAfter(LocalDateTime timestamp);
}
