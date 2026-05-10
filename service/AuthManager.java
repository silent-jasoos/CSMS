package com.cybershield.service;

import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import com.cybershield.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * Application service responsible for authenticating users and issuing
 * JWT tokens within the CyberShield platform.
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Validates credentials against the BCrypt-hashed password stored in
 *       the database.</li>
 *   <li>Enforces a progressive account-lockout policy after repeated
 *       authentication failures.</li>
 *   <li>Issues a signed JWT on successful authentication, encoding the
 *       username and role for stateless downstream authorisation.</li>
 *   <li>Emits structured audit log entries via {@link AttackLogger} for
 *       every authentication outcome (success, failure, lock).</li>
 * </ul>
 *
 * <h2>Account lockout policy</h2>
 * <pre>
 *   failed attempts &lt; 3  → increment counter, return "Invalid credentials"
 *   failed attempts ≥ 3  → lock account for 15 minutes, reset counter
 *   account locked        → return time remaining, reject immediately
 *   successful login      → reset counter, clear lock, record last login
 * </pre>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
@Service
public class AuthManager {

    private static final Logger logger = LoggerFactory.getLogger(AuthManager.class);

    /** Duration of the account lock imposed after {@value #MAX_FAILED_ATTEMPTS} failures. */
    private static final int LOCK_DURATION_MINUTES = 15;

    /** Number of consecutive failures before the account is locked. */
    private static final int MAX_FAILED_ATTEMPTS = 3;

    private final UserRepository      userRepository;
    private final JwtTokenProvider    jwtTokenProvider;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AttackLogger        attackLogger;

    /**
     * Constructs an {@code AuthManager} with all required dependencies.
     *
     * @param userRepository  repository for loading and persisting {@link User} entities
     * @param jwtTokenProvider service for generating signed JWT tokens
     * @param passwordEncoder  BCrypt encoder used to verify raw passwords against
     *                         stored hashes
     * @param attackLogger    central security event logger
     */
    public AuthManager(UserRepository userRepository,
                       JwtTokenProvider jwtTokenProvider,
                       BCryptPasswordEncoder passwordEncoder,
                       AttackLogger attackLogger) {
        this.userRepository   = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder  = passwordEncoder;
        this.attackLogger     = attackLogger;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Authenticates a user by username and password and, on success, returns
     * a signed JWT together with the user's role and display name.
     *
     * <h3>Processing pipeline</h3>
     * <ol>
     *   <li><b>User lookup</b> – loads the {@link User} entity by username;
     *       throws {@link RuntimeException} if not found (generic message to
     *       prevent username enumeration).</li>
     *   <li><b>Active check</b> – rejects inactive accounts before password
     *       comparison to avoid leaking timing information.</li>
     *   <li><b>Lock check</b> – if {@code lockedUntil} is set and is still in
     *       the future, the remaining lock time is computed and returned in a
     *       user-friendly message. The remaining minutes are rounded up by
     *       adding 1 to the {@link ChronoUnit#MINUTES} difference so that a
     *       lock expiring in 30 seconds reports "1 minute" rather than "0 minutes".</li>
     *   <li><b>Password verification</b> – {@link BCryptPasswordEncoder#matches}
     *       compares the raw submitted password against the stored BCrypt hash.
     *       On failure: increment {@code failedLoginAttempts}; if the new count
     *       reaches {@value #MAX_FAILED_ATTEMPTS}, lock the account for
     *       {@value #LOCK_DURATION_MINUTES} minutes and reset the counter.
     *       Always persist and log before throwing.</li>
     *   <li><b>Success path</b> – reset failure counter, clear lock,
     *       record {@code lastLoginAt} and {@code lastLoginIP}, persist,
     *       log the success event.</li>
     *   <li><b>Token generation</b> – generate a JWT encoding username and role.</li>
     *   <li><b>Response assembly</b> – return an immutable map containing
     *       {@code token}, {@code role}, and {@code username}.</li>
     * </ol>
     *
     * @param username  the username submitted by the client
     * @param password  the raw (plain-text) password submitted by the client;
     *                  never stored — used only for BCrypt comparison
     * @param ipAddress the source IP address of the login request, recorded in
     *                  audit logs and stored as {@code lastLoginIP} on success
     * @return an immutable {@link Map} with keys:
     *         <ul>
     *           <li>{@code "token"} – the signed JWT string</li>
     *           <li>{@code "role"} – the user's role name (e.g. {@code "ADMIN"})</li>
     *           <li>{@code "username"} – the authenticated username</li>
     *         </ul>
     * @throws RuntimeException if the user is not found, the account is
     *                          inactive, the account is locked, or the
     *                          credentials are invalid
     */
    @Transactional
    public Map<String, Object> login(String username, String password, String ipAddress) {

        // ------------------------------------------------------------------
        // Step 1 – User lookup
        // ------------------------------------------------------------------
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.warn("Login attempt for non-existent user: '{}' from IP: {}",
                            username, ipAddress);
                    return new RuntimeException("User not found");
                });

        // ------------------------------------------------------------------
        // Step 2 – Active account check
        // ------------------------------------------------------------------
        if (!user.getIsActive()) {
            logger.warn("Login attempt on inactive account: '{}' from IP: {}",
                    username, ipAddress);
            throw new RuntimeException("Account is inactive. Please contact an administrator.");
        }

        // ------------------------------------------------------------------
        // Step 3 – Lock check
        // ------------------------------------------------------------------
        if (user.getLockedUntil() != null
                && user.getLockedUntil().isAfter(LocalDateTime.now())) {

            long minutesLeft = ChronoUnit.MINUTES.between(
                    LocalDateTime.now(), user.getLockedUntil()) + 1;

            logger.warn("Login attempt on locked account: '{}' — {} minute(s) remaining",
                    username, minutesLeft);

            throw new RuntimeException(
                    "Account locked. Try again in " + minutesLeft + " minutes.");
        }

        // ------------------------------------------------------------------
        // Step 4 – Password verification
        // ------------------------------------------------------------------
        if (!passwordEncoder.matches(password, user.getPassword())) {

            int newFailCount = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(newFailCount);

            if (newFailCount >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
                user.setFailedLoginAttempts(0);
                userRepository.save(user);

                attackLogger.logAccountLocked(username, ipAddress);
                attackLogger.logLoginFail(username, ipAddress, newFailCount);

                logger.warn("Account '{}' locked for {} minutes after {} failures",
                        username, LOCK_DURATION_MINUTES, newFailCount);

                throw new RuntimeException(
                        "Account locked due to too many failed attempts. "
                        + "Try again in " + LOCK_DURATION_MINUTES + " minutes.");
            }

            userRepository.save(user);
            attackLogger.logLoginFail(username, ipAddress, newFailCount);

            logger.warn("Failed login for '{}' — attempt {} of {}",
                    username, newFailCount, MAX_FAILED_ATTEMPTS);

            throw new RuntimeException("Invalid credentials.");
        }

        // ------------------------------------------------------------------
        // Step 5 – Success path: reset counters, record login metadata
        // ------------------------------------------------------------------
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(LocalDateTime.now());
        user.setLastLoginIP(ipAddress);
        userRepository.save(user);

        attackLogger.logLoginSuccess(username, ipAddress);
        logger.info("Successful login for '{}' from IP: {}", username, ipAddress);

        // ------------------------------------------------------------------
        // Step 6 – JWT generation
        // ------------------------------------------------------------------
        String token = jwtTokenProvider.generateToken(
                user.getUsername(), user.getRole().name());

        // ------------------------------------------------------------------
        // Step 7 – Response assembly
        // ------------------------------------------------------------------
        return Map.of(
                "token",    token,
                "role",     user.getRole().name(),
                "username", user.getUsername()
        );
    }
}
