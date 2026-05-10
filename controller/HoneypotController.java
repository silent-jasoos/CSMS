package com.cybershield.controller;

import com.cybershield.model.HoneypotCapture;
import com.cybershield.repository.HoneypotCaptureRepository;
import com.cybershield.service.AttackLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * HoneypotController manages the honeypot subsystem of CyberShield CSMS.
 *
 * <p>This controller is intentionally designed to look like a legitimate login page
 * to lure attackers. It captures attacker credentials, IP addresses, and browser
 * fingerprints for security analysis.</p>
 *
 * <p>Two controller paradigms are combined in one class:
 * <ul>
 *   <li>{@code @Controller} – serves the Thymeleaf honeypot login view</li>
 *   <li>{@code @RestController} – exposes REST APIs for capture data and admin controls</li>
 * </ul>
 * </p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@Controller
@CrossOrigin
public class HoneypotController {

    /** Repository for persisting captured attacker credentials and metadata. */
    @Autowired
    private HoneypotCaptureRepository honeypotCaptureRepository;

    /** Service that records honeypot interactions to the central attack log. */
    @Autowired
    private AttackLogger attackLogger;

    /**
     * Tracks whether the honeypot is currently active.
     * Toggled via {@code POST /api/honeypot/toggle}.
     */
    private final AtomicBoolean honeypotActive = new AtomicBoolean(true);

    // -------------------------------------------------------------------------
    // GET /honeypot/login  — Thymeleaf view
    // -------------------------------------------------------------------------

    /**
     * Serves the honeypot login page rendered by the Thymeleaf template engine.
     *
     * <p>The page is designed to resemble a legitimate corporate login portal in order
     * to capture attacker credentials. No authentication is required to access it.</p>
     *
     * @return the Thymeleaf view name {@code "honeypot-login"}
     */
    @GetMapping("/honeypot/login")
    public String honeypotLoginPage() {
        return "honeypot-login";
    }

    // -------------------------------------------------------------------------
    // POST /honeypot/login  — REST capture endpoint
    // -------------------------------------------------------------------------

    /**
     * Captures and persists attacker credentials submitted to the honeypot login form.
     *
     * <p>Extracts the client IP, submitted username, password, and browser User-Agent
     * string. Persists a {@link HoneypotCapture} record and forwards the event to
     * {@link AttackLogger#logHoneypotCapture(HoneypotCapture)} for audit logging.</p>
     *
     * @param capturedUsername  the username submitted by the attacker via form parameter
     * @param capturedPassword  the password submitted by the attacker via form parameter
     * @param request           the raw HTTP request (used to extract IP and User-Agent)
     * @return a {@link Map} with a single {@code "status"} key set to {@code "captured"}
     */
    @PostMapping("/honeypot/login")
    @ResponseBody
    public Map<String, String> captureLogin(
            @RequestParam String capturedUsername,
            @RequestParam String capturedPassword,
            HttpServletRequest request) {

        String capturedIP   = request.getRemoteAddr();
        String browserInfo  = request.getHeader("User-Agent");

        HoneypotCapture capture = new HoneypotCapture();
        capture.setCapturedIP(capturedIP);
        capture.setCapturedUsername(capturedUsername);
        capture.setCapturedPassword(capturedPassword);
        capture.setBrowserInfo(browserInfo);
        capture.setCapturedAt(LocalDateTime.now());

        honeypotCaptureRepository.save(capture);
        attackLogger.logHoneypotCapture(capture);

        return Map.of("status", "captured");
    }

    // -------------------------------------------------------------------------
    // GET /api/honeypot/captures  (ADMIN only)
    // -------------------------------------------------------------------------

    /**
     * Returns all honeypot capture records for administrative review.
     *
     * <p>Only users with the {@code ROLE_ADMIN} authority may access this endpoint.
     * The full list of captured credentials and metadata is returned without pagination
     * for simplicity; add {@code Pageable} if the dataset grows large.</p>
     *
     * @return a {@link List} of all {@link HoneypotCapture} entities
     */
    @GetMapping("/api/honeypot/captures")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public List<HoneypotCapture> getAllCaptures() {
        return honeypotCaptureRepository.findAll();
    }

    // -------------------------------------------------------------------------
    // POST /api/honeypot/toggle
    // -------------------------------------------------------------------------

    /**
     * Toggles the active state of the honeypot subsystem.
     *
     * <p>Intended for demo and testing purposes. Each call flips the current active flag
     * and returns the new state. In a production system this would persist the state and
     * update the request filter chain accordingly.</p>
     *
     * @return a {@link Map} with an {@code "active"} key reflecting the new toggled state
     */
    @PostMapping("/api/honeypot/toggle")
    @ResponseBody
    public Map<String, Boolean> toggleHoneypot() {
        boolean newState = honeypotActive.get() ? false : true;
        honeypotActive.set(newState);
        return Map.of("active", newState);
    }
}
