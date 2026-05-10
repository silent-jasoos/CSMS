package com.cybershield.model;

import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import java.time.LocalDateTime;

/**
 * ================================================================
 * BaseEntity - INHERITANCE Pattern Base Class
 * ================================================================
 *
 * PURPOSE:
 * This is the base class for ALL entity classes in CyberShield CSMS.
 * Every entity (User, Device, Alert, Log, etc.) extends this class
 * to automatically inherit three common fields:
 *
 *   - id         : unique identifier for every record in database
 *   - createdAt  : timestamp when the record was first created
 *   - updatedAt  : timestamp when the record was last modified
 *
 * DESIGN PATTERN USED:
 * INHERITANCE — Child classes extend BaseEntity and automatically
 * get all these fields without rewriting them.
 *
 * Example:
 *   public class User extends BaseEntity { ... }
 *   public class Device extends BaseEntity { ... }
 *   public class Alert extends BaseEntity { ... }
 *
 * @MappedSuperclass:
 * Tells JPA — "share these fields with child classes
 * but do NOT create a separate table for BaseEntity itself."
 * Only child class tables get these columns.
 *
 * ENCAPSULATION:
 * All fields are private — accessed only through
 * public getters and setters defined below.
 *
 * @author CyberShield Development Team
 * @version 1.0
 */
@MappedSuperclass
public abstract class BaseEntity {

    // ============================================================
    // FIELDS (private — Encapsulation)
    // ============================================================

    /**
     * Primary key for every entity in the database.
     * Auto incremented by MySQL (1, 2, 3, 4 ...)
     * @Id        → marks this as the primary key
     * @GeneratedValue → MySQL auto generates the value
     * IDENTITY  → uses MySQL auto_increment
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Timestamp when this record was first saved to database.
     * Set automatically by @PrePersist — you never set this manually.
     * Example: 2024-01-15T10:30:00
     */
    private LocalDateTime createdAt;

    /**
     * Timestamp when this record was last updated in database.
     * Set automatically by @PrePersist and @PreUpdate.
     * Every time you save changes, this updates automatically.
     * Example: 2024-01-16T14:45:00
     */
    private LocalDateTime updatedAt;


    // ============================================================
    // JPA LIFECYCLE METHODS
    // These run automatically — you never call them manually
    // ============================================================

    /**
     * @PrePersist — runs automatically BEFORE a new record
     * is inserted into the database for the first time.
     *
     * Sets BOTH createdAt and updatedAt to current time.
     *
     * Example:
     * User user = new User();
     * userRepository.save(user);
     * ↓
     * @PrePersist fires automatically
     * ↓
     * createdAt = 2024-01-15T10:30:00
     * updatedAt = 2024-01-15T10:30:00
     */
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * @PreUpdate — runs automatically BEFORE an existing
     * record is updated in the database.
     *
     * Only updates updatedAt to current time.
     * createdAt stays the same — it never changes after creation.
     *
     * Example:
     * user.setName("Ahmed");
     * userRepository.save(user);
     * ↓
     * @PreUpdate fires automatically
     * ↓
     * updatedAt = 2024-01-16T14:45:00  ← updated
     * createdAt = 2024-01-15T10:30:00  ← stays same
     */
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }


    // ============================================================
    // GETTERS AND SETTERS
    // ENCAPSULATION — private fields accessed through
    // public methods only
    // ============================================================

    /**
     * Returns the unique ID of this entity.
     * @return Long id
     */
    public Long getId() {
        return id;
    }

    /**
     * Sets the ID of this entity.
     * Note: Normally you never call this manually —
     * MySQL auto generates the ID.
     * @param id the id to set
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Returns the timestamp when this record was created.
     * @return LocalDateTime createdAt
     */
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    /**
     * Sets the createdAt timestamp.
     * Note: Normally you never call this manually —
     * @PrePersist sets this automatically.
     * @param createdAt the timestamp to set
     */
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    /**
     * Returns the timestamp when this record was last updated.
     * @return LocalDateTime updatedAt
     */
    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Sets the updatedAt timestamp.
     * Note: Normally you never call this manually —
     * @PrePersist and @PreUpdate set this automatically.
     * @param updatedAt the timestamp to set
     */
    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

}