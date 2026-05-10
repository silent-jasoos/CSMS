package com.cybershield.controller;

import com.cybershield.model.Alert;
import com.cybershield.repository.AlertRepository;
import com.cybershield.service.IDSScanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * IDSController exposes REST endpoints for the Intrusion Detection System (IDS)
 * module of CyberShield CSMS.
 *
 * <p>Base path: {@code /api/ids}</p>
 *
 * <p>Provides operations to:
 * <ul>
 *   <li>List and page through security alerts</li>
 *   <li>Resolve individual alerts</li>
 *   <li>Simulate attack scenarios for training and testing</li>
 *   <li>Query the count of currently active (unresolved) threats</li>
 * </ul>
 * </p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/ids")
@CrossOrigin
public class IDSController {

    /** Repository for querying and persisting {@link Alert} entities. */
    @Autowired
    private AlertRepository alertRepository;

    /** IDS scanning service that detects threats and maintains active threat state. */
    @Autowired
    private IDSScanner idsScanner;

    // -------------------------------------------------------------------------
    // GET /api/ids/alerts
    // -------------------------------------------------------------------------

    /**
     * Returns a paginated list of all IDS alerts.
     *
     * <p>Pagination and sorting are controlled by Spring's {@link Pageable} mechanism.
     * Clients may pass {@code ?page=0&size=20&sort=detectedAt,desc} query parameters.</p>
     *
     * @param pageable pagination and sorting parameters injected by Spring MVC
     * @return {@link ResponseEntity} containing a {@link Page} of {@link Alert} objects
     */
    @GetMapping("/alerts")
    public ResponseEntity<Page<Alert>> getAlerts(Pageable pageable) {
        Page<Alert> alerts = alertRepository.findAll(pageable);
        return ResponseEntity.ok(alerts);
    }

    // -------------------------------------------------------------------------
    // PUT /api/ids/alerts/{id}/resolve
    // -------------------------------------------------------------------------

    /**
     * Marks a specific alert as resolved.
     *
     * <p>Finds the alert by its primary key, sets {@code isResolved} to {@code true},
     * persists the change, and returns the updated entity. Returns {@code 404} if the
     * alert ID does not exist.</p>
     *
     * @param id the primary key of the {@link Alert} to resolve
     * @return {@link ResponseEntity} with the updated {@link Alert}, or {@code 404} if not found
     */
    @PutMapping("/alerts/{id}/resolve")
    public ResponseEntity<?> resolveAlert(@PathVariable Long id) {
        return alertRepository.findById(id).map(alert -> {
            alert.setResolved(true);
            Alert updated = alertRepository.save(alert);
            return ResponseEntity.ok(updated);
        }).orElse(ResponseEntity.notFound().build());
    }

    // -------------------------------------------------------------------------
    // POST /api/ids/simulate
    // -------------------------------------------------------------------------

    /**
     * Triggers an attack simulation for training or demonstration purposes.
     *
     * <p>Accepts a JSON body with {@code attackType} (e.g., "SQL_INJECTION", "PORT_SCAN")
     * and {@code sourceIP} fields. Delegates execution to
     * {@link IDSScanner#simulateAttack(String, String)}.</p>
     *
     * @param body a {@link Map} containing {@code "attackType"} (String) and
     *             {@code "sourceIP"} (String) keys
     * @return {@link ResponseEntity} containing a confirmation message string
     */
    @PostMapping("/simulate")
    public ResponseEntity<String> simulate(@RequestBody Map<String, String> body) {
        String attackType = body.get("attackType");
        String sourceIP   = body.get("sourceIP");
        idsScanner.simulateAttack(attackType, sourceIP);
        return ResponseEntity.ok("Simulation triggered");
    }

    // -------------------------------------------------------------------------
    // GET /api/ids/alerts/active-count
    // -------------------------------------------------------------------------

    /**
     * Returns the current count of active (unresolved) threats tracked by the IDS scanner.
     *
     * <p>The count is sourced directly from the in-memory state of {@link IDSScanner}
     * rather than hitting the database, providing a real-time figure.</p>
     *
     * @return {@link ResponseEntity} containing a {@link Map} with a single {@code "count"} key
     */
    @GetMapping("/alerts/active-count")
    public ResponseEntity<Map<String, Long>> getActiveCount() {
        long count = idsScanner.getActiveThreatCount();
        return ResponseEntity.ok(Map.of("count", count));
    }
}
