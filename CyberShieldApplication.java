package com.cybershield;

import com.cybershield.model.Role;
import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * CyberShieldApplication is the main entry point for the CyberShield Cyber Security
 * Management System (CSMS) Spring Boot application.
 *
 * <p>On startup, Spring Boot auto-configures all components discovered via component
 * scanning within the {@code com.cybershield} package and sub-packages, including:
 * <ul>
 *   <li>JPA repositories and entity mappings</li>
 *   <li>REST controllers and Thymeleaf view controllers</li>
 *   <li>Spring Security filter chain and JWT provider</li>
 *   <li>Service beans (FirewallEngine, IDSScanner, AttackLogger, etc.)</li>
 * </ul>
 * </p>
 *
 * <p>A {@link CommandLineRunner} bean seeds the database with three default users
 * (admin, analyst, viewer) if they do not already exist, enabling immediate access
 * after a fresh deployment.</p>
 *
 * @author CyberShield Team
 * @version 1.0
 */
@SpringBootApplication
public class CyberShieldApplication {

    /**
     * Application entry point.
     *
     * <p>Delegates to {@link SpringApplication#run(Class, String[])} which bootstraps
     * the embedded Tomcat server, initialises the Spring application context, and
     * triggers all {@link CommandLineRunner} beans after the context is ready.</p>
     *
     * @param args command-line arguments passed to the JVM (forwarded to Spring)
     */
    public static void main(String[] args) {
        SpringApplication.run(CyberShieldApplication.class, args);
    }

    // -------------------------------------------------------------------------
    // Database Seeder
    // -------------------------------------------------------------------------

    /**
     * Initialises the database with default user accounts if they do not already exist.
     *
     * <p>Three accounts are created on first run:
     * <ol>
     *   <li><strong>admin</strong> / {@code Admin@123} – full {@code ADMIN} role,
     *       can manage firewall rules, view all logs, and access admin APIs</li>
     *   <li><strong>analyst1</strong> / {@code Analyst@123} – {@code ANALYST} role,
     *       can resolve IDS alerts and view logs but cannot modify firewall rules</li>
     *   <li><strong>student1</strong> / {@code Student@123} – {@code VIEWER} role,
     *       read-only access for learning and demonstration purposes</li>
     * </ol>
     * </p>
     *
     * <p>Passwords are hashed with {@link BCryptPasswordEncoder} before being persisted;
     * plaintext passwords are never stored in the database.</p>
     *
     * <p>The runner is idempotent: re-running the application against an existing
     * database will not create duplicate accounts.</p>
     *
     * @param userRepo the {@link UserRepository} used to check existence and persist new users
     * @param encoder  the {@link BCryptPasswordEncoder} bean used to hash passwords
     * @return a {@link CommandLineRunner} executed once the application context is fully started
     */
    @Bean
    public CommandLineRunner initDatabase(UserRepository userRepo,
                                         BCryptPasswordEncoder encoder) {
        return args -> {

            // -----------------------------------------------------------------
            // Seed: Admin user
            // -----------------------------------------------------------------
            if (!userRepo.existsByUsername("admin")) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("Admin@123"));
                admin.setRole(Role.ADMIN);
                admin.setActive(true);
                userRepo.save(admin);
            }

            // -----------------------------------------------------------------
            // Seed: Analyst user
            // -----------------------------------------------------------------
            if (!userRepo.existsByUsername("analyst1")) {
                User analyst = new User();
                analyst.setUsername("analyst1");
                analyst.setPassword(encoder.encode("Analyst@123"));
                analyst.setRole(Role.ANALYST);
                analyst.setActive(true);
                userRepo.save(analyst);
            }

            // -----------------------------------------------------------------
            // Seed: Viewer / Student user
            // -----------------------------------------------------------------
            if (!userRepo.existsByUsername("student1")) {
                User student = new User();
                student.setUsername("student1");
                student.setPassword(encoder.encode("Student@123"));
                student.setRole(Role.VIEWER);
                student.setActive(true);
                userRepo.save(student);
            }

            // -----------------------------------------------------------------
            // Startup banner
            // -----------------------------------------------------------------
            System.out.println("=== CyberShield CSMS Started! Default users created. ===");
            System.out.println("Admin:    admin    / Admin@123");
            System.out.println("Analyst:  analyst1 / Analyst@123");
            System.out.println("Student:  student1 / Student@123");
            System.out.println("Access:   http://localhost:8080");
        };
    }
}
