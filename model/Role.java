package com.cybershield.model;

/**
 * ================================================================
 * Role - User Access Level Enum
 * ================================================================
 *
 * PURPOSE:
 * Defines the three user access levels in CyberShield CSMS.
 * Controls what each user can see and do in the system.
 *
 * USED BY:
 * Spring Security @PreAuthorize annotations to control
 * endpoint access throughout the application.
 *
 * Example usage in controllers:
 *   @PreAuthorize("hasRole('ADMIN')")
 *   public String adminOnlyPage() { ... }
 *
 *   @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
 *   public String analyzeThreats() { ... }
 *
 * ACCESS LEVELS:
 *
 *   ADMIN    → Full system access
 *              Can create users, configure system,
 *              view all data, delete records
 *
 *   ANALYST  → View and analyze only
 *              Can view threats, generate reports,
 *              analyze security events
 *
 *   VIEWER   → Monitoring access only
 *              Can only view dashboard and
 *              basic monitoring screens
 *
 * DESIGN PATTERN:
 * Enum with fields — each role carries its own
 * displayName and description automatically.
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
public enum Role {

    // ============================================================
    // ENUM VALUES
    // Each value calls the constructor below automatically
    // ============================================================

    /**
     * ADMIN — Full system access.
     * Can manage users, configure system settings,
     * view all security data and delete records.
     */
    ADMIN(
        "Administrator",
        "Full system access"
    ),

    /**
     * ANALYST — View and analyze security data only.
     * Can view threats, generate reports and
     * analyze security events but cannot manage users.
     */
    ANALYST(
        "Security Analyst",
        "View and analyze only"
    ),

    /**
     * VIEWER — Basic monitoring access only.
     * Can only view dashboard and
     * basic monitoring screens. Read only.
     */
    VIEWER(
        "Viewer/Student",
        "Monitoring access only"
    );


    // ============================================================
    // FIELDS (private — Encapsulation)
    // ============================================================

    /**
     * Human readable name of the role.
     * Used for displaying in UI instead of raw enum name.
     * Example: "Administrator" instead of "ADMIN"
     */
    private final String displayName;

    /**
     * Short description of what this role can do.
     * Used for tooltips, user management screens.
     * Example: "Full system access"
     */
    private final String description;


    // ============================================================
    // CONSTRUCTOR
    // Enums have private constructors
    // Called automatically when each value is defined above
    // ============================================================

    /**
     * Constructor for Role enum.
     * Automatically called when ADMIN, ANALYST, VIEWER are defined.
     *
     * @param displayName  human readable name shown in UI
     * @param description  short description of access level
     */
    Role(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }


    // ============================================================
    // GETTERS
    // No setters — enum values are FINAL, never changed
    // ============================================================

    /**
     * Returns the human readable display name of this role.
     * Use this when showing role name in UI or reports.
     *
     * Example:
     *   Role.ADMIN.getDisplayName()    → "Administrator"
     *   Role.ANALYST.getDisplayName()  → "Security Analyst"
     *   Role.VIEWER.getDisplayName()   → "Viewer/Student"
     *
     * @return String displayName
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Returns the description of what this role can do.
     * Use this for tooltips or user management screens.
     *
     * Example:
     *   Role.ADMIN.getDescription()    → "Full system access"
     *   Role.ANALYST.getDescription()  → "View and analyze only"
     *   Role.VIEWER.getDescription()   → "Monitoring access only"
     *
     * @return String description
     */
    public String getDescription() {
        return description;
    }

}