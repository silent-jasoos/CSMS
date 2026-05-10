package com.cybershield.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Servlet filter that intercepts every HTTP request exactly once, extracts a
 * JWT Bearer token from the {@code Authorization} header, validates it, and —
 * if valid — populates the Spring Security
 * {@link org.springframework.security.core.context.SecurityContext} with the
 * authenticated principal for the duration of that request.
 *
 * <h2>Why {@link OncePerRequestFilter}?</h2>
 * <p>In a Servlet container, a single logical request can pass through the
 * filter chain multiple times (e.g. after a {@code RequestDispatcher.forward()},
 * an error dispatch, or an async re-dispatch). Extending
 * {@link OncePerRequestFilter} guarantees that
 * {@link #doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
 * is invoked <em>at most once per request</em>, regardless of internal
 * dispatching, preventing redundant token parsing and context pollution.
 *
 * <h2>Stateless authentication model</h2>
 * <p>Unlike form-based login, which relies on server-side {@link jakarta.servlet.http.HttpSession},
 * JWT authentication is entirely stateless:
 * <ol>
 *   <li>The client authenticates once (e.g. via {@code POST /api/auth/login})
 *       and receives a signed JWT.</li>
 *   <li>On every subsequent request the client sends the JWT in the
 *       {@code Authorization: Bearer <token>} header.</li>
 *   <li>This filter validates the token cryptographically, reloads the user's
 *       current details (including real-time lock status) from the data store,
 *       and places the resulting
 *       {@link UsernamePasswordAuthenticationToken} into the
 *       {@link SecurityContextHolder} for the lifetime of the current thread.</li>
 *   <li>At the end of the request the {@link SecurityContextHolder} is
 *       automatically cleared by Spring Security's
 *       {@code SecurityContextPersistenceFilter} (or its Spring Security 6
 *       successor {@code SecurityContextHolderFilter}).</li>
 * </ol>
 *
 * <h2>Filter placement in the security chain</h2>
 * <p>This filter is registered in {@code SecurityConfig} via:
 * <pre>{@code
 *   http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
 * }</pre>
 * Placing it <em>before</em> {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter}
 * ensures that the {@link SecurityContextHolder} is already populated when
 * Spring Security's authorization checks run, so form-login processing is never
 * triggered for requests that already carry a valid JWT.
 *
 * <h2>Security considerations</h2>
 * <ul>
 *   <li><b>No re-authentication if context is already set</b> – if another
 *       filter has already populated the context (e.g. during testing or
 *       integration scenarios), this filter does not overwrite it.</li>
 *   <li><b>Silent failure on invalid tokens</b> – a missing, malformed, or
 *       expired token does not throw an exception here; the filter simply does
 *       not set the security context, and downstream authorization checks will
 *       reject the request with HTTP 401 via the configured
 *       {@link org.springframework.security.web.AuthenticationEntryPoint}.</li>
 *   <li><b>Real-time user reload</b> – calling
 *       {@link CustomUserDetailsService#loadUserByUsername(String)} on every
 *       request ensures that account-lock changes take effect immediately,
 *       without waiting for the current JWT to expire.</li>
 * </ul>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     JwtTokenProvider
 * @see     CustomUserDetailsService
 * @see     OncePerRequestFilter
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    /** HTTP header name that carries the Bearer token on every authenticated request. */
    private static final String AUTHORIZATION_HEADER = "Authorization";

    /** Required prefix for the Authorization header value; the token follows after this prefix. */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Responsible for generating, parsing, and validating JWTs.
     * Used here to validate the incoming token and extract the username claim.
     */
    private final JwtTokenProvider jwtProvider;

    /**
     * Loads the full {@link UserDetails} — including granted authorities and
     * real-time lock status — from the data store by username.
     * Invoked after successful token validation to reconstruct the security principal.
     */
    private final CustomUserDetailsService userDetailsService;

    /**
     * Constructs a {@code JwtAuthenticationFilter} with all required collaborators.
     *
     * <p>Constructor injection is used to make both dependencies mandatory, immutable
     * ({@code final}), and easily mockable in unit tests without a Spring context.
     *
     * @param jwtProvider        the token utility for validation and claim extraction;
     *                           must not be {@code null}
     * @param userDetailsService the service for loading live user details from the store;
     *                           must not be {@code null}
     */
    public JwtAuthenticationFilter(JwtTokenProvider jwtProvider,
                                   CustomUserDetailsService userDetailsService) {
        this.jwtProvider        = jwtProvider;
        this.userDetailsService = userDetailsService;
    }

    // =========================================================================
    // OncePerRequestFilter contract
    // =========================================================================

    /**
     * Core filter logic: extracts, validates, and processes the JWT Bearer token
     * present in the {@code Authorization} header of the incoming HTTP request.
     *
     * <h3>Processing pipeline</h3>
     * <pre>
     *  ┌─────────────────────────────────────────────────────────────────┐
     *  │ 1. Extract token from "Authorization: Bearer <token>" header    │
     *  │    ├─ Header absent or no "Bearer " prefix  → skip, continue   │
     *  │    └─ Token string extracted                → proceed           │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 2. Validate token via JwtTokenProvider                          │
     *  │    ├─ Invalid / expired / tampered          → skip, continue   │
     *  │    └─ Valid signature, not expired           → proceed          │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 3. Check SecurityContext — avoid overwriting existing auth      │
     *  │    ├─ Already authenticated                 → skip, continue   │
     *  │    └─ Context is empty                      → proceed          │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 4. Load UserDetails (live DB lookup for lock/role refresh)      │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 5. Build UsernamePasswordAuthenticationToken with authorities   │
     *  │    and attach request-specific WebAuthenticationDetails         │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 6. Set token in SecurityContextHolder                           │
     *  ├─────────────────────────────────────────────────────────────────┤
     *  │ 7. chain.doFilter(request, response) — always executed          │
     *  └─────────────────────────────────────────────────────────────────┘
     * </pre>
     *
     * <h3>Step 5 — {@link UsernamePasswordAuthenticationToken} construction</h3>
     * <p>The three-argument constructor is used intentionally:
     * <ul>
     *   <li>{@code principal} – the loaded {@link UserDetails} object (not just the username string),
     *       so that downstream code (e.g. {@code @AuthenticationPrincipal}) can access
     *       the full user object.</li>
     *   <li>{@code credentials} – {@code null}: the raw password is never needed after
     *       initial authentication and must not be stored in the security context to
     *       prevent accidental exposure in logs or serialized sessions.</li>
     *   <li>{@code authorities} – the {@link org.springframework.security.core.GrantedAuthority}
     *       collection loaded from the database, reflecting any role changes since the
     *       token was issued.</li>
     * </ul>
     * Passing authorities to the constructor marks the token as
     * <em>authenticated</em> ({@code isAuthenticated() == true}), which is what
     * Spring Security checks before allowing access to protected resources.
     *
     * <h3>Step 5 — {@link WebAuthenticationDetailsSource}</h3>
     * <p>{@code auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request))}
     * attaches the remote IP address and session ID (if any) to the authentication token.
     * This data is available to audit logs, intrusion-detection listeners, and
     * {@link org.springframework.security.authentication.event.AuthenticationSuccessEvent}
     * handlers — useful in a CyberShield context for correlating access with source IPs.
     *
     * <h3>Step 7 — {@code chain.doFilter} always runs</h3>
     * <p>The filter chain is always advanced regardless of whether authentication
     * succeeded. This is intentional: permit-all endpoints (e.g. {@code /api/auth/**})
     * must be reachable without a token, and it is the downstream authorization layer
     * (not this filter) that enforces access control.
     *
     * @param request  the incoming HTTP request; never {@code null}
     * @param response the outgoing HTTP response; never {@code null}
     * @param chain    the remaining filter chain to invoke after this filter;
     *                 never {@code null}
     * @throws ServletException if a downstream filter or servlet throws a
     *                          {@link ServletException}
     * @throws IOException      if a downstream filter or servlet throws an
     *                          {@link IOException}
     */
    @Override
    protected void doFilterInternal(HttpServletRequest  request,
                                    HttpServletResponse response,
                                    FilterChain         chain)
            throws ServletException, IOException {

        // ------------------------------------------------------------------
        // Step 1 – Extract Bearer token from the Authorization header
        // ------------------------------------------------------------------
        String header = request.getHeader(AUTHORIZATION_HEADER);

        if (!StringUtils.hasText(header) || !header.startsWith(BEARER_PREFIX)) {
            logger.trace("No Bearer token found on request [{}]; skipping JWT authentication",
                    request.getRequestURI());
            chain.doFilter(request, response);
            return;
        }

        // Trim the "Bearer " prefix (7 characters) to obtain the raw JWT string
        String token = header.substring(BEARER_PREFIX.length());

        // ------------------------------------------------------------------
        // Step 2 – Validate the token (signature, expiry, structure)
        // ------------------------------------------------------------------
        if (!jwtProvider.validateToken(token)) {
            // validateToken() logs the specific failure reason internally;
            // we do not set authentication — downstream authorization will
            // respond with HTTP 401 via the configured AuthenticationEntryPoint.
            logger.debug("JWT validation failed for request [{}]", request.getRequestURI());
            chain.doFilter(request, response);
            return;
        }

        // ------------------------------------------------------------------
        // Step 3 – Skip if the SecurityContext is already populated
        //          (e.g. by another filter earlier in the chain)
        // ------------------------------------------------------------------
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.trace("SecurityContext already populated; skipping JWT processing for [{}]",
                    request.getRequestURI());
            chain.doFilter(request, response);
            return;
        }

        // ------------------------------------------------------------------
        // Step 4 – Extract username and reload live UserDetails from the store
        // ------------------------------------------------------------------
        String      username    = jwtProvider.getUsernameFromToken(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        logger.debug("JWT authenticated user '{}' for request [{}] — authorities: {}",
                username, request.getRequestURI(), userDetails.getAuthorities());

        // ------------------------------------------------------------------
        // Step 5 – Build the authentication token
        //   • principal   = full UserDetails (not just the username string)
        //   • credentials = null  (raw password must never live in the context)
        //   • authorities = live roles loaded from the database
        // ------------------------------------------------------------------
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        // Attach remote IP and session metadata for audit/IDS event listeners
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // ------------------------------------------------------------------
        // Step 6 – Publish the authentication to the SecurityContextHolder
        // ------------------------------------------------------------------
        SecurityContextHolder.getContext().setAuthentication(auth);

        // ------------------------------------------------------------------
        // Step 7 – Always advance the filter chain
        // ------------------------------------------------------------------
        chain.doFilter(request, response);
    }
}