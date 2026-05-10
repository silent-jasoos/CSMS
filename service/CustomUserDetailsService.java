package com.cybershield.security;

import com.cybershield.repository.UserRepository;
import com.cybershield.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Custom implementation of Spring Security's {@link UserDetailsService} that
 * loads user-specific data from the CyberShield data store during authentication.
 *
 * <h2>Role in the Spring Security authentication flow</h2>
 * <p>When a login request arrives, Spring Security's
 * {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
 * calls {@link #loadUserByUsername(String)} to retrieve a fully populated
 * {@link UserDetails} object. The provider then:
 * <ol>
 *   <li>Compares the submitted raw password against
 *       {@link UserDetails#getPassword()} using the configured
 *       {@link org.springframework.security.crypto.password.PasswordEncoder}
 *       (BCrypt in this application).</li>
 *   <li>Checks the account-status flags ({@code isEnabled()},
 *       {@code isAccountNonLocked()}, etc.) and throws the appropriate
 *       {@link org.springframework.security.core.AuthenticationException}
 *       subclass if any flag is violated.</li>
 *   <li>Populates the
 *       {@link org.springframework.security.core.context.SecurityContext}
 *       with a {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
 *       on success.</li>
 * </ol>
 *
 * <p>This service is also invoked on every subsequent request by
 * {@link JwtAuthenticationFilter} to reconstruct the security context from a
 * validated JWT, ensuring that account-lock status is re-evaluated on each
 * request rather than only at initial login.
 *
 * <h2>Account locking strategy</h2>
 * <p>The {@code lockedUntil} field on the {@link User} entity stores the
 * {@link LocalDateTime} until which the account is locked (e.g. after repeated
 * failed login attempts). The lock check is performed at load time:
 * <pre>{@code
 *   accountLocked = (user.getLockedUntil() != null
 *                    && user.getLockedUntil().isAfter(LocalDateTime.now()))
 * }</pre>
 * A {@code null} value means the account has never been locked, and a
 * {@code lockedUntil} in the past means the lock has naturally expired — both
 * cases result in {@code accountLocked = false}.
 * Spring Security maps {@code accountLocked = true} to
 * {@link org.springframework.security.authentication.LockedException} during
 * authentication, which surfaces as an HTTP 401 with a descriptive message.
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 * @see     UserDetailsService
 * @see     UserDetails
 * @see     UserRepository
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);

    /**
     * Repository used to look up {@link User} entities by username.
     *
     * <p>Injected via constructor to guarantee immutability and to make the
     * dependency explicit for unit-testing (no Spring context required to
     * instantiate this service with a mock repository).
     */
    private final UserRepository userRepository;

    /**
     * Constructs a {@code CustomUserDetailsService} with its required repository.
     *
     * @param userRepository the JPA repository for {@link User} entity lookups;
     *                       must not be {@code null}
     */
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // =========================================================================
    // UserDetailsService contract
    // =========================================================================

    /**
     * Locates a {@link UserDetails} representation of the user identified by
     * {@code username}, including password hash, granted roles, and real-time
     * account-lock status.
     *
     * <h3>Processing steps</h3>
     * <ol>
     *   <li><b>Repository lookup</b> – delegates to
     *       {@link UserRepository#findByUsername(String)}, which issues a single
     *       {@code SELECT} against the {@code users} table.</li>
     *   <li><b>Not-found guard</b> – if no record exists, throws
     *       {@link UsernameNotFoundException}. Spring Security catches this and
     *       maps it to a generic "Bad credentials" response to prevent username
     *       enumeration attacks.</li>
     *   <li><b>Lock evaluation</b> – {@code lockedUntil} is compared against
     *       {@link LocalDateTime#now()} at load time so that time-based unlocks
     *       take effect automatically without any scheduled job or admin action.</li>
     *   <li><b>UserDetails construction</b> – uses the built-in
     *       {@link org.springframework.security.core.userdetails.User} builder
     *       to assemble the principal. {@code .roles(role)} automatically prefixes
     *       the role string with {@code "ROLE_"} and wraps it in a
     *       {@link org.springframework.security.core.authority.SimpleGrantedAuthority},
     *       satisfying Spring Security's authority-naming convention.</li>
     * </ol>
     *
     * <h3>Returned {@link UserDetails} flag mapping</h3>
     * <table border="1" cellpadding="4">
     *   <tr><th>{@code UserDetails} flag</th><th>Value</th><th>Derives from</th></tr>
     *   <tr>
     *     <td>{@code isEnabled()}</td>
     *     <td>{@code true}</td>
     *     <td>Implicit default from builder; extend to {@code user.isEnabled()}
     *         if an active/inactive flag is added to the entity.</td>
     *   </tr>
     *   <tr>
     *     <td>{@code isAccountNonLocked()}</td>
     *     <td>{@code !(lockedUntil != null && lockedUntil.isAfter(now))}</td>
     *     <td>{@link User#getLockedUntil()} compared to
     *         {@link LocalDateTime#now()} at load time.</td>
     *   </tr>
     *   <tr>
     *     <td>{@code isAccountNonExpired()}</td>
     *     <td>{@code true}</td>
     *     <td>Implicit default; extend when account-expiry is needed.</td>
     *   </tr>
     *   <tr>
     *     <td>{@code isCredentialsNonExpired()}</td>
     *     <td>{@code true}</td>
     *     <td>Implicit default; extend for forced password-rotation policies.</td>
     *   </tr>
     * </table>
     *
     * <h3>Transaction note</h3>
     * <p>{@code @Transactional(readOnly = true)} opens a read-only transaction
     * for this method. This signals to the JPA provider that no dirty-checking
     * or flush is required, allowing Hibernate to skip snapshot generation and
     * the underlying JDBC driver to enable read-only optimizations, improving
     * throughput under high authentication load.
     *
     * @param username the username identifying the user whose data is required;
     *                 never {@code null} when called by Spring Security
     * @return a fully populated, immutable {@link UserDetails} object representing
     *         the found user, ready for password comparison and authority extraction
     * @throws UsernameNotFoundException if no user with the given {@code username}
     *                                   exists in the data store
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        logger.debug("Loading UserDetails for username: '{}'", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.warn("Authentication failed — user not found: '{}'", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        boolean isLocked = user.getLockedUntil() != null
                && user.getLockedUntil().isAfter(LocalDateTime.now());

        if (isLocked) {
            logger.warn("Authentication attempted on locked account: '{}' (locked until {})",
                    username, user.getLockedUntil());
        }

        logger.debug("UserDetails built successfully for '{}' — role: {}, locked: {}",
                username, user.getRole(), isLocked);

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().name())
                .accountLocked(isLocked)
                .build();
    }
}