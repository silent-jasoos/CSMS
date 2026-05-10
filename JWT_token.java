package com.cybershield.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * JwtTokenProvider is a Spring-managed component responsible for all JWT
 * (JSON Web Token) lifecycle operations within the CyberShield security layer.
 *
 * <p>A JWT is a compact, URL-safe token composed of three Base64URL-encoded
 * segments separated by dots: {@code Header.Payload.Signature}.
 * <ul>
 *   <li><b>Header</b> – declares the token type ("JWT") and signing algorithm (e.g. HS256).</li>
 *   <li><b>Payload</b> – carries <em>claims</em>: statements about the subject
 *       (username, role) plus standard metadata (issuedAt, expiration).</li>
 *   <li><b>Signature</b> – HMAC-SHA256 digest of the encoded header + payload,
 *       keyed with {@code jwt.secret}, guaranteeing integrity and authenticity.</li>
 * </ul>
 *
 * <p>This implementation targets the <b>JJWT 0.12.3</b> fluent API.
 * Notable 0.12.x changes vs. the legacy 0.9.x API:
 * <ul>
 *   <li>{@code Jwts.parserBuilder()} is replaced by {@code Jwts.parser()}.</li>
 *   <li>{@code signWith(key, algorithm)} overload is unified into
 *       {@code signWith(key)} when the key already encodes the algorithm.</li>
 *   <li>Parser returns a typed {@code Jws<Claims>} via {@code parseSignedClaims()}
 *       instead of the old {@code parseClaimsJws()}.</li>
 * </ul>
 *
 * <p>Required {@code application.properties} / {@code application.yml} entries:
 * <pre>
 *   jwt.secret=&lt;Base64-or-raw 32-byte secret&gt;
 *   jwt.expiration=86400000   # milliseconds (e.g. 24 h)
 * </pre>
 *
 * @author  CyberShield Engineering
 * @version 1.0
 * @since   2026-05-10
 */
@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    /**
     * The HMAC secret injected from {@code jwt.secret} in application configuration.
     *
     * <p>Must be at least 256 bits (32 characters) long to satisfy the HS256
     * minimum key-length requirement mandated by RFC 7518 §3.2.
     * Store this value in a secrets manager or encrypted property source —
     * never hard-code it in source control.
     */
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * Token time-to-live in <em>milliseconds</em>, injected from
     * {@code jwt.expiration} in application configuration.
     *
     * <p>Example: {@code 86400000} represents 24 hours.
     * Short-lived tokens reduce the attack window if a token is compromised.
     */
    @Value("${jwt.expiration}")
    private long expiration;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Generates a signed JWT token encoding the caller's identity and role.
     *
     * <p><b>JWT construction steps (JJWT 0.12.3):</b>
     * <ol>
     *   <li>{@code Jwts.builder()} – opens a new {@link io.jsonwebtoken.JwtBuilder}.</li>
     *   <li>{@code .subject(username)} – sets the {@code sub} registered claim,
     *       identifying the principal this token represents.</li>
     *   <li>{@code .claim("role", role)} – adds a private/custom claim carrying
     *       the user's authorization role (e.g. {@code "ROLE_ADMIN"}).</li>
     *   <li>{@code .issuedAt(new Date())} – sets the {@code iat} registered claim
     *       to the current UTC instant, enabling age-based validation.</li>
     *   <li>{@code .expiration(new Date(...))} – sets the {@code exp} registered claim;
     *       parsers will reject tokens presented after this timestamp.</li>
     *   <li>{@code .signWith(buildKey())} – signs the header+payload with
     *       HMAC-SHA256, producing the token's integrity-protected signature.</li>
     *   <li>{@code .compact()} – serializes the JWT to its three-part
     *       {@code xxxxx.yyyyy.zzzzz} string representation.</li>
     * </ol>
     *
     * @param username the authenticated principal's username; becomes the JWT {@code sub} claim
     * @param role     the user's authority string (e.g. {@code "ROLE_USER"}); stored as a custom claim
     * @return a compact, signed JWT string ready for inclusion in an
     *         {@code Authorization: Bearer <token>} header
     */
    public String generateToken(String username, String role) {
        Date now       = new Date();
        Date expiresAt = new Date(System.currentTimeMillis() + expiration);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiresAt)
                .signWith(buildKey())
                .compact();
    }

    /**
     * Extracts the {@code sub} (subject) claim from a validated JWT.
     *
     * <p>The subject claim ({@code sub}) is a registered JWT claim defined in
     * RFC 7519 §4.1.2. In this application it carries the authenticated
     * user's username, which is used to reload the {@link org.springframework.security.core.userdetails.UserDetails}
     * during request authentication.
     *
     * @param token the compact JWT string (without the {@code Bearer } prefix)
     * @return the username embedded in the token's {@code sub} claim
     * @throws JwtException             if the token is malformed, tampered, or expired
     * @throws IllegalArgumentException if {@code token} is null or empty
     */
    public String getUsernameFromToken(String token) {
        return getAllClaims(token).getSubject();
    }

    /**
     * Extracts the custom {@code role} claim from a validated JWT.
     *
     * <p>The {@code role} claim is a <em>private claim</em> (RFC 7519 §4.3)
     * defined by this application to carry the user's granted authority
     * (e.g. {@code "ROLE_ADMIN"}, {@code "ROLE_USER"}). It is written during
     * token generation via {@link #generateToken(String, String)} and read here
     * to reconstruct the security context on subsequent requests.
     *
     * @param token the compact JWT string
     * @return the role string stored in the {@code role} claim, or {@code null}
     *         if the claim is absent
     * @throws JwtException             if the token is invalid
     * @throws IllegalArgumentException if {@code token} is null or empty
     */
    public String getRoleFromToken(String token) {
        return getAllClaims(token).get("role", String.class);
    }

    /**
     * Validates a JWT token for authenticity, integrity, and freshness.
     *
     * <p><b>Validation checks performed by JJWT 0.12.3:</b>
     * <ul>
     *   <li><b>Signature</b> – re-computes the HMAC-SHA256 digest and compares it
     *       to the token's signature segment; detects any tampering of header or payload.</li>
     *   <li><b>Expiration ({@code exp})</b> – rejects tokens whose {@code exp} claim
     *       is before the current UTC time (with a configurable clock-skew tolerance).</li>
     *   <li><b>Structure</b> – ensures the token has exactly three Base64URL-encoded
     *       segments; rejects malformed strings immediately.</li>
     * </ul>
     *
     * <p>Any {@link JwtException} subclass (e.g. {@code ExpiredJwtException},
     * {@code MalformedJwtException}, {@code SignatureException},
     * {@code UnsupportedJwtException}) or {@link IllegalArgumentException} is caught,
     * logged at {@code ERROR} level, and causes the method to return {@code false},
     * allowing the caller to respond with an appropriate HTTP 401.
     *
     * @param token the compact JWT string received from the client
     * @return {@code true} if the token is structurally valid, correctly signed,
     *         and has not yet expired; {@code false} otherwise
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = getAllClaims(token);
            // JJWT already throws ExpiredJwtException if exp has passed,
            // but we perform an explicit guard for clarity and future overrides.
            boolean notExpired = claims.getExpiration().after(new Date());
            if (!notExpired) {
                logger.error("JWT token is expired");
                return false;
            }
            return true;
        } catch (JwtException ex) {
            logger.error("Invalid JWT token — JwtException: {}", ex.getMessage());
            return false;
        } catch (IllegalArgumentException ex) {
            logger.error("Invalid JWT token — IllegalArgumentException: {}", ex.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Parses the JWT and returns its {@link Claims} payload.
     *
     * <p><b>JJWT 0.12.3 parsing pipeline:</b>
     * <ol>
     *   <li>{@code Jwts.parser()} – creates a new {@link io.jsonwebtoken.JwtParserBuilder}.</li>
     *   <li>{@code .verifyWith(buildKey())} – supplies the verification key;
     *       the parser will use it to validate the HMAC-SHA256 signature.</li>
     *   <li>{@code .build()} – constructs an immutable, thread-safe {@link io.jsonwebtoken.JwtParser}.</li>
     *   <li>{@code .parseSignedClaims(token)} – decodes, verifies, and returns
     *       a {@code Jws<Claims>} wrapper (replaces the 0.9.x {@code parseClaimsJws()}).</li>
     *   <li>{@code .getPayload()} – unwraps the verified {@link Claims} map.</li>
     * </ol>
     *
     * <p>This method is intentionally {@code private}: all callers should go through
     * the typed accessor methods ({@link #getUsernameFromToken}, {@link #getRoleFromToken},
     * {@link #validateToken}) rather than operating on raw {@link Claims} directly.
     *
     * @param token the compact JWT string to parse and verify
     * @return the verified {@link Claims} payload
     * @throws JwtException             if the signature is invalid, the token is expired,
     *                                  or the token is otherwise malformed
     * @throws IllegalArgumentException if {@code token} is null or blank
     */
    private Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(buildKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Derives a type-safe {@link SecretKey} from the raw {@code jwt.secret} string.
     *
     * <p>{@link Keys#hmacShaKeyFor(byte[])} interprets the supplied bytes as an
     * HMAC key and selects the strongest HMAC-SHA algorithm the key length supports:
     * <ul>
     *   <li>≥ 32 bytes → HS256</li>
     *   <li>≥ 48 bytes → HS384</li>
     *   <li>≥ 64 bytes → HS512</li>
     * </ul>
     *
     * <p>Converting {@code secretKey} with {@link String#getBytes()} uses the
     * platform default charset; for portable deployments consider
     * {@code secretKey.getBytes(StandardCharsets.UTF_8)}.
     *
     * @return a {@link SecretKey} suitable for HMAC-SHA signing and verification
     */
    private SecretKey buildKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
