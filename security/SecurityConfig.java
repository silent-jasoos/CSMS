package com.cybershield.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Central Spring Security configuration for the CyberShield REST API.
 *
 * <h2>Architecture overview</h2>
 * <p>Spring Security 6 (shipped with Spring Boot 3) replaced the
 * {@code WebSecurityConfigurerAdapter} extend-and-override pattern with a
 * purely bean-based model. This class declares every security concern as an
 * explicit {@link Bean}, making each piece independently testable and
 * replaceable without subclassing framework internals.
 *
 * <h2>Filter-chain execution order</h2>
 * <pre>
 *  Incoming request
 *      │
 *      ▼
 *  JwtAuthenticationFilter          ← validates Bearer token, loads SecurityContext
 *      │
 *      ▼
 *  UsernamePasswordAuthenticationFilter  ← skipped for stateless JWT flows
 *      │
 *      ▼
 *  Authorization checks             ← role-based rules defined in filterChain()
 *      │
 *      ▼
 *  Dispatcher / Controller
 * </pre>
 *
 * <h2>Key security choices</h2>
 * <ul>
 *   <li><b>CSRF disabled</b> – CSRF attacks rely on browser cookie auto-submission.
 *       Because this API uses stateless JWT Bearer tokens (never cookies), there is
 *       no session cookie to hijack and CSRF protection adds no value here.</li>
 *   <li><b>Stateless sessions</b> – {@code STATELESS} policy prevents Spring Security
 *       from ever creating or consulting an {@code HttpSession}, ensuring horizontal
 *       scalability and eliminating server-side session state.</li>
 *   <li><b>BCrypt password encoding</b> – BCrypt is an adaptive, salted hash function
 *       purposefully slow against brute-force attacks. The default work-factor (10)
 *       balances security and latency; increase it as hardware improves.</li>
 * </ul>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     JwtAuthenticationFilter
 * @see     CustomUserDetailsService
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * The stateless JWT authentication filter that intercepts every request,
     * extracts and validates the Bearer token, and populates the
     * {@link org.springframework.security.core.context.SecurityContext}
     * before the standard Spring Security filter chain continues.
     */
    private final JwtAuthenticationFilter jwtFilter;

    /**
     * Custom implementation of {@link org.springframework.security.core.userdetails.UserDetailsService}
     * that loads user credentials and granted authorities from the application's
     * data store. Used by {@link DaoAuthenticationProvider} during login and by
     * the JWT filter when reconstructing the security context per request.
     */
    private final CustomUserDetailsService userDetailsService;

    /**
     * Jackson {@link ObjectMapper} used to serialize the JSON error body
     * returned by the custom {@link AuthenticationEntryPoint}.
     * Declared as a field so the same instance is reused across requests.
     */
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Constructs a {@code SecurityConfig} with all required collaborators.
     *
     * <p>Constructor injection is preferred over field injection for
     * mandatory dependencies: it makes dependencies explicit, enables
     * immutability ({@code final} fields), and simplifies unit testing.
     *
     * @param jwtFilter          the JWT validation filter to add to the chain
     * @param userDetailsService the service that loads user details from the store
     */
    public SecurityConfig(JwtAuthenticationFilter jwtFilter,
                          CustomUserDetailsService userDetailsService) {
        this.jwtFilter           = jwtFilter;
        this.userDetailsService  = userDetailsService;
    }

    // =========================================================================
    // Core security filter chain
    // =========================================================================

    /**
     * Defines the primary {@link SecurityFilterChain} governing all HTTP request
     * authorization for the CyberShield API.
     *
     * <h3>Authorization matrix</h3>
     * <table border="1" cellpadding="4">
     *   <tr><th>Path pattern</th><th>Required authority</th><th>Rationale</th></tr>
     *   <tr><td>{@code /api/auth/**}</td><td>Public</td>
     *       <td>Login / registration endpoints must be reachable before a token exists.</td></tr>
     *   <tr><td>{@code /honeypot/login}</td><td>Public</td>
     *       <td>Honeypot trap must be publicly reachable to attract real attackers.</td></tr>
     *   <tr><td>{@code /css/**, /js/**, /images/**}</td><td>Public</td>
     *       <td>Static assets for any embedded UI or API docs.</td></tr>
     *   <tr><td>{@code /error}</td><td>Public</td>
     *       <td>Spring Boot's default error endpoint; must be open to avoid 401 loops.</td></tr>
     *   <tr><td>{@code /dashboard}</td><td>ADMIN</td>
     *       <td>Administrative overview dashboard.</td></tr>
     *   <tr><td>{@code /api/users/**}</td><td>ADMIN</td>
     *       <td>User management; only admins may create, modify, or delete accounts.</td></tr>
     *   <tr><td>{@code /api/honeypot/toggle}</td><td>ADMIN</td>
     *       <td>Toggling the honeypot changes network posture; admin-only.</td></tr>
     *   <tr><td>{@code /api/ids/**, /api/logs/**, /api/reports/**, /api/firewall/**}</td>
     *       <td>ADMIN or ANALYST</td>
     *       <td>Security operations data readable by analysts, writable by admins
     *           (method-level security further restricts mutations).</td></tr>
     *   <tr><td>All others</td><td>Any authenticated user</td>
     *       <td>Default deny-unless-authenticated posture.</td></tr>
     * </table>
     *
     * <h3>Exception handling</h3>
     * <p>Unauthenticated requests to protected resources trigger the custom
     * {@link AuthenticationEntryPoint} which writes a machine-readable JSON
     * error body with HTTP 401, avoiding HTML error pages that confuse REST clients.
     *
     * @param http the {@link HttpSecurity} builder provided by Spring
     * @return the fully configured and built {@link SecurityFilterChain}
     * @throws Exception if any configuration step fails during build
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            // -----------------------------------------------------------------
            // CSRF – disabled: stateless JWT API, no cookie-based sessions
            // -----------------------------------------------------------------
            .csrf(AbstractHttpConfigurer::disable)

            // -----------------------------------------------------------------
            // Session management – never create or use HttpSession
            // -----------------------------------------------------------------
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // -----------------------------------------------------------------
            // Authorization rules – evaluated top-to-bottom; first match wins
            // -----------------------------------------------------------------
            .authorizeHttpRequests(auth -> auth

                // --- Public endpoints ---
                .requestMatchers(
                    "/api/auth/**",
                    "/honeypot/login",
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/error"
                ).permitAll()

                // --- Admin-only endpoints ---
                .requestMatchers(
                    "/dashboard",
                    "/api/users/**",
                    "/api/honeypot/toggle"
                ).hasRole("ADMIN")

                // --- Admin or Analyst endpoints ---
                .requestMatchers(
                    "/api/ids/**",
                    "/api/logs/**",
                    "/api/reports/**",
                    "/api/firewall/**"
                ).hasAnyRole("ADMIN", "ANALYST")

                // --- All remaining requests require authentication ---
                .anyRequest().authenticated()
            )

            // -----------------------------------------------------------------
            // Exception handling – custom 401 JSON response for unauthenticated
            // requests; Spring Security's default redirects to a login page
            // which is inappropriate for a REST API.
            // -----------------------------------------------------------------
            .exceptionHandling(ex ->
                ex.authenticationEntryPoint(restAuthenticationEntryPoint()))

            // -----------------------------------------------------------------
            // Authentication provider – wires BCrypt + UserDetailsService
            // into the standard DAO-based authentication flow
            // -----------------------------------------------------------------
            .authenticationProvider(daoAuthenticationProvider())

            // -----------------------------------------------------------------
            // JWT filter – placed BEFORE Spring's form-login filter so that
            // every request is token-validated before any username/password
            // processing could occur (form login is effectively disabled here).
            // -----------------------------------------------------------------
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // =========================================================================
    // Authentication infrastructure
    // =========================================================================

    /**
     * Configures a {@link DaoAuthenticationProvider} that integrates
     * {@link CustomUserDetailsService} with BCrypt password verification.
     *
     * <p>The {@code DaoAuthenticationProvider} is the standard Spring Security
     * component responsible for:
     * <ol>
     *   <li>Loading a {@link org.springframework.security.core.userdetails.UserDetails}
     *       instance via {@code userDetailsService.loadUserByUsername(username)}.</li>
     *   <li>Comparing the raw password submitted at login against the stored
     *       BCrypt hash using the injected {@link PasswordEncoder}.</li>
     *   <li>Returning a fully populated {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
     *       on success, or throwing an {@link org.springframework.security.core.AuthenticationException}
     *       on failure.</li>
     * </ol>
     *
     * <p>Explicitly registering this provider (rather than relying on
     * auto-configuration) prevents Spring Security from creating a second
     * default {@code UserDetailsService} bean and removes the
     * "Using generated security password" warning on startup.
     *
     * @return a configured {@link DaoAuthenticationProvider}
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * Exposes the {@link AuthenticationManager} as a Spring bean so that
     * the authentication service (e.g. {@code AuthService}) can call
     * {@code authenticationManager.authenticate(token)} programmatically
     * during the login flow.
     *
     * <p>In Spring Security 6, the {@link AuthenticationManager} is no longer
     * automatically exposed as a bean. It must be retrieved explicitly from
     * {@link AuthenticationConfiguration#getAuthenticationManager()}, which
     * returns the fully wired manager that delegates to all registered
     * {@link org.springframework.security.authentication.AuthenticationProvider}s
     * (including our {@link DaoAuthenticationProvider} above).
     *
     * @param config the auto-configured {@link AuthenticationConfiguration}
     *               provided by Spring Boot
     * @return the application's primary {@link AuthenticationManager}
     * @throws Exception if the manager cannot be built (e.g. missing UserDetailsService)
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Provides the application-wide {@link PasswordEncoder} using the BCrypt
     * adaptive hashing algorithm.
     *
     * <p><b>Why BCrypt?</b>
     * <ul>
     *   <li><b>Salted</b> – each hash embeds a unique 128-bit random salt,
     *       making precomputed rainbow-table attacks infeasible.</li>
     *   <li><b>Adaptive cost</b> – the work factor (default: 10 rounds) can be
     *       increased over time as hardware becomes faster, keeping brute-force
     *       attack costs high without invalidating existing hashes.</li>
     *   <li><b>Slow by design</b> – BCrypt deliberately requires ~100 ms per
     *       hash at cost 10, slowing online and offline attacks without
     *       meaningfully impacting legitimate login latency.</li>
     * </ul>
     *
     * <p>To increase the work factor (e.g. when deploying on faster hardware):
     * <pre>{@code
     *     return new BCryptPasswordEncoder(12); // 2^12 rounds instead of 2^10
     * }</pre>
     *
     * @return a {@link BCryptPasswordEncoder} with the default strength of 10
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // =========================================================================
    // Custom authentication entry point
    // =========================================================================

    /**
     * Returns a custom {@link AuthenticationEntryPoint} that writes a
     * structured JSON error response for unauthenticated requests.
     *
     * <h3>Why a custom entry point?</h3>
     * <p>Spring Security's default entry point redirects the browser to
     * {@code /login}, which is useless (and misleading) for REST clients.
     * This implementation instead:
     * <ul>
     *   <li>Sets HTTP status {@code 401 Unauthorized}.</li>
     *   <li>Sets {@code Content-Type: application/json}.</li>
     *   <li>Writes a JSON body containing the timestamp, status, error message,
     *       and request path — enough context for clients to act without
     *       leaking internal stack traces.</li>
     * </ul>
     *
     * <h3>Sample response body</h3>
     * <pre>
     * {
     *   "timestamp": "2026-05-10T10:15:30Z",
     *   "status":    401,
     *   "error":     "Unauthorized",
     *   "message":   "Full authentication is required to access this resource",
     *   "path":      "/api/ids/alerts"
     * }
     * </pre>
     *
     * @return a lambda-based {@link AuthenticationEntryPoint} that serializes
     *         the error as JSON with HTTP 401
     */
    @Bean
    public AuthenticationEntryPoint restAuthenticationEntryPoint() {
        return (HttpServletRequest request,
                HttpServletResponse response,
                AuthenticationException authException) -> {

            logger.warn("Unauthorized access attempt on [{}] — {}",
                    request.getRequestURI(), authException.getMessage());

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("timestamp", Instant.now().toString());
            body.put("status",    HttpStatus.UNAUTHORIZED.value());
            body.put("error",     "Unauthorized");
            body.put("message",   authException.getMessage());
            body.put("path",      request.getRequestURI());

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");

            objectMapper.writeValue(response.getOutputStream(), body);
        };
    }
}