package com.cybershield.service;

import com.cybershield.model.FirewallRule;
import com.cybershield.repository.FirewallRuleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Stateless service that evaluates incoming network traffic against the
 * active ruleset stored in the CyberShield firewall rules table and returns
 * an {@code ALLOW} or {@code BLOCK} verdict.
 *
 * <h2>Rule evaluation model</h2>
 * <p>Rules are loaded from the database ordered by {@code priority} ascending
 * (lowest number = highest precedence). The engine walks the list and returns
 * the verdict of the <em>first matching rule</em>. If no rule matches, a
 * default {@code ALLOW} policy is applied. This is a <b>first-match</b> model,
 * equivalent to the behaviour of most hardware firewalls and iptables chains.
 *
 * <h2>Matching semantics</h2>
 * <table border="1" cellpadding="4">
 *   <tr><th>Dimension</th><th>Wildcard / any value</th><th>Match logic</th></tr>
 *   <tr><td>IP</td><td>{@code 0.0.0.0} or {@code *}</td><td>Matches all IPs</td></tr>
 *   <tr><td>IP</td><td>{@code 192.168.*}</td><td>Prefix match on subnet</td></tr>
 *   <tr><td>IP</td><td>{@code 192.168.1.10}</td><td>Exact match</td></tr>
 *   <tr><td>Port</td><td>{@code 0} or {@code null}</td><td>Matches all ports</td></tr>
 *   <tr><td>Port</td><td>any integer</td><td>Exact match</td></tr>
 *   <tr><td>Protocol</td><td>{@code BOTH}</td><td>Matches TCP and UDP</td></tr>
 *   <tr><td>Protocol</td><td>{@code TCP} / {@code UDP}</td><td>Case-insensitive exact match</td></tr>
 * </table>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
@Service
public class FirewallEngine {

    private static final Logger logger = LoggerFactory.getLogger(FirewallEngine.class);

    /** Default priority value used in the response when no rule matches. */
    private static final int DEFAULT_PRIORITY = 999;

    private final FirewallRuleRepository firewallRuleRepository;
    private final AttackLogger           attackLogger;

    /**
     * Constructs a {@code FirewallEngine} with its required dependencies.
     *
     * @param firewallRuleRepository repository for loading active firewall rules
     * @param attackLogger           central security event logger
     */
    public FirewallEngine(FirewallRuleRepository firewallRuleRepository,
                          AttackLogger attackLogger) {
        this.firewallRuleRepository = firewallRuleRepository;
        this.attackLogger           = attackLogger;
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Evaluates a network connection attempt against the active firewall
     * ruleset and returns the matching verdict.
     *
     * <h3>Evaluation steps</h3>
     * <ol>
     *   <li>Load all active rules from the database ordered by
     *       {@code priority ASC} so that high-precedence rules are checked
     *       first.</li>
     *   <li>For each rule, test all three dimensions (IP, port, protocol)
     *       using the private matcher methods. A rule matches only when
     *       <em>all three</em> dimensions match simultaneously.</li>
     *   <li>On the first match, log a {@code FIREWALL_BLOCK} event if the
     *       action is {@code "BLOCK"}, then return the verdict map.</li>
     *   <li>If no rule matches after the full traversal, return the default
     *       {@code ALLOW} policy with priority {@value #DEFAULT_PRIORITY}.</li>
     * </ol>
     *
     * <h3>Return map keys</h3>
     * <ul>
     *   <li>{@code "result"} – {@code "ALLOW"} or {@code "BLOCK"}</li>
     *   <li>{@code "matchedRule"} – name of the matching rule, or
     *       {@code "Default Policy"} when no rule matched</li>
     *   <li>{@code "priority"} – integer priority of the matched rule</li>
     * </ul>
     *
     * @param ipAddress the source IP address of the connection attempt
     * @param port      the destination port of the connection attempt
     * @param protocol  the transport protocol: {@code "TCP"} or {@code "UDP"}
     * @return an immutable {@link Map} containing the verdict, matched rule
     *         name, and rule priority
     */
    public Map<String, Object> checkTraffic(String ipAddress, int port, String protocol) {

        List<FirewallRule> rules =
                firewallRuleRepository.findByIsActiveTrueOrderByPriorityAsc();

        logger.debug("Evaluating traffic: IP={} port={} proto={} against {} active rule(s)",
                ipAddress, port, protocol, rules.size());

        for (FirewallRule rule : rules) {
            if (matchesIP(ipAddress, rule.getIpAddress())
                    && matchesPort(port, rule.getPortNumber())
                    && matchesProtocol(protocol, rule.getProtocol())) {

                String action = rule.getAction();

                if ("BLOCK".equalsIgnoreCase(action)) {
                    attackLogger.logFirewallBlock(ipAddress, port, rule.getRuleName());
                    logger.info("FIREWALL BLOCK — IP={} port={} proto={} rule=[{}]",
                            ipAddress, port, protocol, rule.getRuleName());
                } else {
                    logger.debug("FIREWALL ALLOW — IP={} port={} proto={} rule=[{}]",
                            ipAddress, port, protocol, rule.getRuleName());
                }

                return Map.of(
                        "result",      action,
                        "matchedRule", rule.getRuleName(),
                        "priority",    rule.getPriority()
                );
            }
        }

        // Default implicit-allow policy — no explicit rule matched
        logger.debug("FIREWALL DEFAULT ALLOW — IP={} port={} proto={}", ipAddress, port, protocol);
        return Map.of(
                "result",      "ALLOW",
                "matchedRule", "Default Policy",
                "priority",    DEFAULT_PRIORITY
        );
    }

    // =========================================================================
    // Private matching helpers
    // =========================================================================

    /**
     * Determines whether the incoming IP address satisfies the IP constraint
     * defined in a firewall rule.
     *
     * <p>Three matching modes are supported:
     * <ul>
     *   <li><b>Wildcard</b> – rule IP is {@code "0.0.0.0"} or {@code "*"}:
     *       matches any incoming IP unconditionally.</li>
     *   <li><b>Subnet prefix</b> – rule IP ends with {@code ".*"}:
     *       the trailing {@code ".*"} is stripped to obtain the prefix, and
     *       the incoming IP is checked with {@link String#startsWith}.
     *       Example: rule {@code "192.168.*"} → prefix {@code "192.168."}
     *       → matches {@code "192.168.1.10"} and {@code "192.168.50.200"}.</li>
     *   <li><b>Exact match</b> – the incoming IP must equal the rule IP
     *       character-for-character.</li>
     * </ul>
     *
     * @param incoming the source IP of the connection being evaluated
     * @param ruleIP   the IP constraint defined on the firewall rule
     * @return {@code true} if the incoming IP satisfies the rule constraint
     */
    private boolean matchesIP(String incoming, String ruleIP) {
        if ("0.0.0.0".equals(ruleIP) || "*".equals(ruleIP)) {
            return true;
        }
        if (ruleIP.endsWith(".*")) {
            String prefix = ruleIP.substring(0, ruleIP.length() - 1); // keep the trailing dot
            return incoming.startsWith(prefix);
        }
        return incoming.equals(ruleIP);
    }

    /**
     * Determines whether the incoming destination port satisfies the port
     * constraint defined in a firewall rule.
     *
     * <p>A rule port value of {@code 0} or {@code null} acts as a wildcard
     * that matches any destination port, allowing rules that apply regardless
     * of port (e.g. a blanket IP block).
     *
     * @param incoming  the destination port of the connection being evaluated
     * @param rulePort  the port constraint defined on the firewall rule;
     *                  {@code null} or {@code 0} means "any port"
     * @return {@code true} if the incoming port satisfies the rule constraint
     */
    private boolean matchesPort(int incoming, Integer rulePort) {
        if (rulePort == null || rulePort == 0) {
            return true;
        }
        return incoming == rulePort;
    }

    /**
     * Determines whether the incoming transport protocol satisfies the
     * protocol constraint defined in a firewall rule.
     *
     * <p>A rule protocol of {@code "BOTH"} matches either {@code "TCP"} or
     * {@code "UDP"}, allowing protocol-agnostic rules. All other comparisons
     * are case-insensitive to tolerate mixed-case input from upstream callers.
     *
     * @param incoming      the transport protocol of the connection:
     *                      {@code "TCP"} or {@code "UDP"}
     * @param ruleProtocol  the protocol constraint defined on the firewall rule
     * @return {@code true} if the incoming protocol satisfies the rule constraint
     */
    private boolean matchesProtocol(String incoming, String ruleProtocol) {
        if ("BOTH".equalsIgnoreCase(ruleProtocol)) {
            return true;
        }
        return incoming.equalsIgnoreCase(ruleProtocol);
    }
}
