package com.cybershield.controller;

import com.cybershield.security.AuthManager;
import com.cybershield.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * AuthController handles all authentication-related HTTP endpoints for CyberShield CSMS.
 *
 * <p>Exposes REST APIs under {@code /api/auth} for login, logout, and current-user retrieval.
 * Cross-origin requests are permitted to support frontend SPA clients.</p>
 *
 * <p>Security flow:
 * <ol>
 *   <li>Client POSTs credentials to {@code /api/auth/login}</li>
 *   <li>{@link AuthManager} validates credentials and returns a JWT token map</li>
 *   <li>Client includes the JWT in subsequent requests via the Authorization header</li>
 *   <li>Client POSTs to {@code /api/auth/logout} to clear the security context</li>
 * </ol>
 * </p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthController {

    /**
     * AuthManager handles credential validation, brute-force lockout logic,
     * and JWT generation upon successful login.
     */
    @Autowired
    private AuthManager authManager;

    /**
     * JwtTokenProvider is injected for potential token-utility operations
     * (e.g., token validation, claims extraction) outside the login flow.
     */
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    // -------------------------------------------------------------------------
    // POST /api/auth/login
    // -------------------------------------------------------------------------

    /**
     * Authenticates a user with the provided username, password, and client IP address.
     *
     * <p>The client IP is extracted from the incoming HTTP request and forwarded to
     * {@link AuthManager#login(String, String, String)} for rate-limiting and audit purposes.</p>
     *
     * <p>Response codes:
     * <ul>
     *   <li>{@code 200 OK} – Login successful; body contains JWT token and user details.</li>
     *   <li>{@code 423 Locked} – Account is temporarily locked due to failed attempts.</li>
     *   <li>{@code 401 Unauthorized} – Invalid credentials or other authentication failure.</li>
     * </ul>
     * </p>
     *
     * @param body    request body map containing {@code "username"} and {@code "password"} keys
     * @param request the raw {@link HttpServletRequest} used to extract the remote client IP
     * @return a {@link ResponseEntity} with either the auth result map or an error map
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body,
                                   HttpServletRequest request) {
        String ip = request.getRemoteAddr();

        try {
            Map<String, Object> result = authManager.login(
                    body.get("username"),
                    body.get("password"),
                    ip
            );
            return ResponseEntity.ok(result);

        } catch (RuntimeException e) {
            int statusCode = e.getMessage() != null && e.getMessage().contains("locked")
                    ? 423
                    : 401;
            return ResponseEntity
                    .status(statusCode)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // -------------------------------------------------------------------------
    // POST /api/auth/logout
    // -------------------------------------------------------------------------

    /**
     * Logs out the currently authenticated user by clearing the Spring Security context.
     *
     * <p>After this call the JWT previously issued to the client is no longer associated
     * with any server-side session. Clients should also discard the token locally.</p>
     *
     * @return a {@link Map} containing a confirmation message
     */
    @PostMapping("/logout")
    public Map<String, String> logout() {
        SecurityContextHolder.clearContext();
        return Map.of("message", "Logged out successfully");
    }

    // -------------------------------------------------------------------------
    // GET /api/auth/me
    // -------------------------------------------------------------------------

    /**
     * Returns the username and role of the currently authenticated principal.
     *
     * <p>The {@link Authentication} object is retrieved from the thread-local
     * {@link SecurityContextHolder}. If no authentication is present the endpoint
     * will be blocked by the security filter chain before this method is reached.</p>
     *
     * @return a {@link Map} containing {@code "username"} and {@code "role"} of the logged-in user
     */
    @GetMapping("/me")
    public Map<String, Object> me() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String role = auth.getAuthorities().stream()
                .findFirst()
                .map(Object::toString)
                .orElse("UNKNOWN");

        return Map.of(
                "username", auth.getName(),
                "role", role
        );
    }
}
