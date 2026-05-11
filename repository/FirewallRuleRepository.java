package com.cybershield.repository;

import com.cybershield.model.FirewallRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA repository for the {@code firewall_rules} table.
 *
 * <p>Provides query methods that the Firewall Engine and Admin UI use to
 * read and manage firewall rules.  Spring generates all SQL automatically.</p>
 */
@Repository
public interface FirewallRuleRepository extends JpaRepository<FirewallRule, Long> {

    /**
     * Retrieves all active firewall rules sorted by priority (lowest number = highest priority).
     * <p>Generated SQL:
     * {@code SELECT * FROM firewall_rules WHERE is_active = TRUE ORDER BY priority ASC}</p>
     * <p><strong>This is the most critical method.</strong> It is called by the firewall engine
     * on every traffic-evaluation cycle to get the ordered list of rules to match against.</p>
     *
     * @return list of active rules ordered from highest to lowest priority
     */
    List<FirewallRule> findByIsActiveTrueOrderByPriorityAsc();

    /**
     * Finds all firewall rules with a given action (either "ALLOW" or "BLOCK").
     * <p>Generated SQL: {@code SELECT * FROM firewall_rules WHERE action = ?}</p>
     * <p>Used by the admin panel to display separate lists of ALLOW and BLOCK rules.</p>
     *
     * @param action the action string — "ALLOW" or "BLOCK"
     * @return list of rules matching that action
     */
    List<FirewallRule> findByAction(String action);

    /**
     * Retrieves all rules where {@code is_active} is TRUE (regardless of priority order).
     * <p>Generated SQL: {@code SELECT * FROM firewall_rules WHERE is_active = TRUE}</p>
     * <p>Used by reporting features that need active rules without a specific sort order.</p>
     *
     * @return list of all active firewall rules
     */
    List<FirewallRule> findByIsActiveTrue();

    /**
     * Counts how many rules are currently active.
     * <p>Generated SQL: {@code SELECT COUNT(*) FROM firewall_rules WHERE is_active = TRUE}</p>
     * <p>Used by the dashboard statistics widget to show the active rule count.</p>
     *
     * @return total number of active firewall rules
     */
    long countByIsActiveTrue();

    /**
     * Looks up a firewall rule by its unique name.
     * <p>Generated SQL: {@code SELECT * FROM firewall_rules WHERE rule_name = ?}</p>
     * <p>Used to check for duplicate rule names before inserting a new rule.</p>
     *
     * @param ruleName the exact rule name to search for
     * @return an Optional containing the rule, or empty if no rule has that name
     */
    Optional<FirewallRule> findByRuleName(String ruleName);
}
