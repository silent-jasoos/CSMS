package com.cybershield.controller;

import com.cybershield.repository.AlertRepository;
import com.cybershield.repository.HoneypotCaptureRepository;
import com.cybershield.repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Map;

/**
 * DashboardController serves both the Thymeleaf dashboard views and the REST API
 * endpoint that supplies real-time statistics to the frontend dashboard.
 *
 * <p>View routes:
 * <ul>
 *   <li>{@code GET /dashboard} – renders the main Thymeleaf dashboard template</li>
 *   <li>{@code GET /home} – renders the landing/home Thymeleaf template</li>
 * </ul>
 * </p>
 *
 * <p>REST route:
 * <ul>
 *   <li>{@code GET /api/dashboard/stats} – returns aggregated security statistics as JSON</li>
 * </ul>
 * </p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@Controller
public class DashboardController {

    /** Repository for querying log entries (today's events, firewall blocks). */
    @Autowired
    private LogRepository logRepository;

    /** Repository for querying unresolved IDS alerts (active threats). */
    @Autowired
    private AlertRepository alertRepository;

    /** Repository for querying honeypot captures made today. */
    @Autowired
    private HoneypotCaptureRepository honeypotCaptureRepository;

    // -------------------------------------------------------------------------
    // GET /dashboard  — Thymeleaf view
    // -------------------------------------------------------------------------

    /**
     * Renders the main security dashboard page using the Thymeleaf template engine.
     *
     * <p>The dashboard template ({@code dashboard.html}) is expected to fetch live
     * data from {@code /api/dashboard/stats} via JavaScript after page load.</p>
     *
     * @return the Thymeleaf view name {@code "dashboard"}
     */
    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    // -------------------------------------------------------------------------
    // GET /home  — Thymeleaf view
    // -------------------------------------------------------------------------

    /**
     * Renders the home / landing page using the Thymeleaf template engine.
     *
     * <p>Accessible to unauthenticated users as a public entry point before login.</p>
     *
     * @return the Thymeleaf view name {@code "home"}
     */
    @GetMapping("/home")
    public String home() {
        return "home";
    }

    // -------------------------------------------------------------------------
    // GET /api/dashboard/stats  — REST endpoint
    // -------------------------------------------------------------------------

    /**
     * Returns a snapshot of key security metrics for the current day.
     *
     * <p>All counts are scoped to the calendar day of the server's local timezone
     * (midnight to now). The returned map contains:
     * <ul>
     *   <li>{@code todayEvents} – total number of log entries recorded today</li>
     *   <li>{@code activeThreats} – number of IDS alerts that have not yet been resolved</li>
     *   <li>{@code blockedConnections} – number of {@code FIREWALL_BLOCK} log events today</li>
     *   <li>{@code honeypotCaptures} – number of honeypot credential captures today</li>
     * </ul>
     * </p>
     *
     * @return a {@link Map} containing the four statistic keys described above
     */
    @GetMapping("/api/dashboard/stats")
    @ResponseBody
    public Map<String, Object> getDashboardStats() {
        LocalDateTime startOfDay = LocalDateTime.now().with(LocalTime.MIDNIGHT);

        long todayEvents         = logRepository.countByTimestampAfter(startOfDay);
        long activeThreats       = alertRepository.countByIsResolvedFalse();
        long blockedConnections  = logRepository.countByEventTypeAndTimestampAfter("FIREWALL_BLOCK", startOfDay);
        long honeypotCaptures    = honeypotCaptureRepository.countByCapturedAtAfter(startOfDay);

        return Map.of(
                "todayEvents",        todayEvents,
                "activeThreats",      activeThreats,
                "blockedConnections", blockedConnections,
                "honeypotCaptures",   honeypotCaptures
        );
    }
}
