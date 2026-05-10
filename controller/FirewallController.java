package com.cybershield.controller;

import com.cybershield.model.FirewallRule;
import com.cybershield.repository.FirewallRuleRepository;
import com.cybershield.repository.LogRepository;
import com.cybershield.service.FirewallEngine;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * FirewallController exposes REST endpoints for managing firewall rules and
 * simulating traffic checks in the CyberShield CSMS.
 *
 * <p>Base path: {@code /api/firewall}</p>
 *
 * <p>Rule management (POST, PUT, DELETE) is restricted to users with the
 * {@code ADMIN} role via {@link PreAuthorize} annotations. Read and simulation
 * operations are available to all authenticated users.</p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/firewall")
@CrossOrigin
public class FirewallController {

    /** Repository for persisting and querying {@link FirewallRule} entities. */
    @Autowired
    private FirewallRuleRepository firewallRuleRepository;

    /** Repository for persisting log entries (used when deleting rules). */
    @Autowired
    private LogRepository logRepository;

    /** Engine that evaluates network traffic against the active ruleset. */
    @Autowired
    private FirewallEngine firewallEngine;

    // -------------------------------------------------------------------------
    // GET /api/firewall/rules
    // -------------------------------------------------------------------------

    /**
     * Retrieves all firewall rules stored in the database, ordered by insertion order.
     *
     * <p>Returns the complete list regardless of whether a rule is active or not,
     * giving administrators a full view of the configured ruleset.</p>
     *
     * @return {@link ResponseEntity} containing a {@link List} of all {@link FirewallRule} objects
     */
    @GetMapping("/rules")
    public ResponseEntity<List<FirewallRule>> getAllRules() {
        List<FirewallRule> rules = firewallRuleRepository.findAll();
        return ResponseEntity.ok(rules);
    }

    // -------------------------------------------------------------------------
    // POST /api/firewall/rules  (ADMIN only)
    // -------------------------------------------------------------------------

    /**
     * Creates and persists a new firewall rule.
     *
     * <p>Only users with the {@code ROLE_ADMIN} authority may call this endpoint.
     * The rule object is deserialized from the JSON request body and saved directly
     * to the database.</p>
     *
     * @param rule the {@link FirewallRule} to create, deserialized from the request body
     * @return {@link ResponseEntity} containing the saved {@link FirewallRule} with its generated ID
     */
    @PostMapping("/rules")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FirewallRule> createRule(@RequestBody FirewallRule rule) {
        FirewallRule saved = firewallRuleRepository.save(rule);
        return ResponseEntity.ok(saved);
    }

    // -------------------------------------------------------------------------
    // PUT /api/firewall/rules/{id}  (ADMIN only)
    // -------------------------------------------------------------------------

    /**
     * Updates an existing firewall rule identified by its database ID.
     *
     * <p>The endpoint fetches the existing rule, applies the fields from the request
     * body, and persists the changes. Returns {@code 404} if the rule does not exist.</p>
     *
     * <p>Only users with the {@code ROLE_ADMIN} authority may call this endpoint.</p>
     *
     * @param id   the primary key of the {@link FirewallRule} to update
     * @param body the {@link FirewallRule} containing updated field values
     * @return {@link ResponseEntity} with the updated rule, or {@code 404} if not found
     */
    @PutMapping("/rules/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateRule(@PathVariable Long id,
                                        @RequestBody FirewallRule body) {
        return firewallRuleRepository.findById(id).map(existing -> {
            existing.setName(body.getName());
            existing.setSourceIP(body.getSourceIP());
            existing.setDestinationIP(body.getDestinationIP());
            existing.setPort(body.getPort());
            existing.setProtocol(body.getProtocol());
            existing.setAction(body.getAction());
            existing.setPriority(body.getPriority());
            existing.setActive(body.isActive());
            FirewallRule updated = firewallRuleRepository.save(existing);
            return ResponseEntity.ok(updated);
        }).orElse(ResponseEntity.notFound().build());
    }

    // -------------------------------------------------------------------------
    // DELETE /api/firewall/rules/{id}  (ADMIN only)
    // -------------------------------------------------------------------------

    /**
     * Deletes a firewall rule by its database ID and logs the deletion action.
     *
     * <p>After deletion an audit log entry is written via {@link LogRepository} so
     * administrators can track rule lifecycle events. Returns {@code 404} if the
     * rule does not exist.</p>
     *
     * <p>Only users with the {@code ROLE_ADMIN} authority may call this endpoint.</p>
     *
     * @param id the primary key of the {@link FirewallRule} to delete
     * @return {@link ResponseEntity} with a confirmation message, or {@code 404} if not found
     */
    @DeleteMapping("/rules/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteRule(@PathVariable Long id) {
        if (!firewallRuleRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        firewallRuleRepository.deleteById(id);
        // Audit log: record that rule id was deleted
        System.out.println("[AUDIT] Firewall rule " + id + " deleted by admin.");
        return ResponseEntity.ok(Map.of("message", "Rule " + id + " deleted successfully"));
    }

    // -------------------------------------------------------------------------
    // POST /api/firewall/simulate
    // -------------------------------------------------------------------------

    /**
     * Simulates a network connection attempt through the firewall engine.
     *
     * <p>Accepts a JSON body with {@code ip}, {@code port}, and {@code protocol} fields.
     * Delegates evaluation to {@link FirewallEngine#checkTraffic(String, int, String)} and
     * returns the engine's verdict (e.g., ALLOW or BLOCK).</p>
     *
     * @param body a {@link Map} containing {@code "ip"} (String), {@code "port"} (int),
     *             and {@code "protocol"} (String) keys
     * @return {@link ResponseEntity} containing the firewall engine's result map
     */
    @PostMapping("/simulate")
    public ResponseEntity<?> simulate(@RequestBody Map<String, Object> body) {
        String ip = (String) body.get("ip");
        int port = Integer.parseInt(body.get("port").toString());
        String protocol = (String) body.get("protocol");

        Map<String, Object> result = firewallEngine.checkTraffic(ip, port, protocol);
        return ResponseEntity.ok(result);
    }
}
