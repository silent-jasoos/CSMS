package com.cybershield.repository;

import com.cybershield.model.User;
import com.cybershield.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for the {@code users} table.
 *
 * <p>Spring automatically generates the SQL for every method below based on
 * the method name — no hand-written SQL needed.</p>
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Looks up a single user by their username.
     * <p>Generated SQL: {@code SELECT * FROM users WHERE username = ?}</p>
     * <p>Used by Spring Security during login to load the UserDetails object.</p>
     *
     * @param username the exact username to search for
     * @return an Optional containing the user, or empty if not found
     */
    Optional<User> findByUsername(String username);

    /**
     * Looks up a single user by their email address.
     * <p>Generated SQL: {@code SELECT * FROM users WHERE email = ?}</p>
     * <p>Used during registration to check for duplicate emails.</p>
     *
     * @param email the email address to search for
     * @return an Optional containing the user, or empty if not found
     */
    Optional<User> findByEmail(String email);

    /**
     * Retrieves all users that have a specific role.
     * <p>Generated SQL: {@code SELECT * FROM users WHERE role = ?}</p>
     * <p>Used by the admin panel to list all ANALYSTs or VIEWERs.</p>
     *
     * @param role the Role enum value (ADMIN, ANALYST, or VIEWER)
     * @return a list of users with that role; empty list if none found
     */
    List<User> findByRole(Role role);

    /**
     * Checks whether a username already exists in the database.
     * <p>Generated SQL: {@code SELECT COUNT(*) > 0 FROM users WHERE username = ?}</p>
     * <p>Used during user registration to prevent duplicate usernames.</p>
     *
     * @param username the username to check
     * @return {@code true} if the username is already taken, {@code false} otherwise
     */
    boolean existsByUsername(String username);

    /**
     * Checks whether an email address already exists in the database.
     * <p>Generated SQL: {@code SELECT COUNT(*) > 0 FROM users WHERE email = ?}</p>
     * <p>Used during registration to prevent duplicate email addresses.</p>
     *
     * @param email the email to check
     * @return {@code true} if the email is already in use, {@code false} otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Retrieves all users whose {@code is_active} flag is TRUE.
     * <p>Generated SQL: {@code SELECT * FROM users WHERE is_active = TRUE}</p>
     * <p>Used by the admin dashboard to display only active accounts.</p>
     *
     * @return list of active users
     */
    List<User> findByIsActiveTrue();

    /**
     * Finds all accounts that are currently locked (lock expiry is in the future).
     * <p>Generated SQL: {@code SELECT * FROM users WHERE locked_until > ?}</p>
     * <p>Used by the security dashboard to show administrators which accounts
     * are still under a time-based lockout.</p>
     *
     * @param now the current date/time; accounts locked until after this value are returned
     * @return list of currently locked user accounts
     */
    List<User> findByLockedUntilAfter(LocalDateTime now);

    /**
     * Counts how many users have a given role.
     * <p>Generated SQL: {@code SELECT COUNT(*) FROM users WHERE role = ?}</p>
     * <p>Used by the admin statistics panel to display role distribution.</p>
     *
     * @param role the Role enum value to count
     * @return the total number of users with that role
     */
    long countByRole(Role role);
}