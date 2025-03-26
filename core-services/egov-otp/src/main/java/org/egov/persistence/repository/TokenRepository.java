package org.egov.persistence.repository;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.egov.domain.exception.TokenUpdateException;
import org.egov.domain.model.Token;
import org.egov.domain.model.TokenSearchCriteria;
import org.egov.domain.model.Tokens;
import org.egov.domain.model.ValidateRequest;
import org.egov.persistence.repository.rowmapper.TokenRowMapper;
import org.egov.web.util.*; // Assuming OtpConfiguration is here or import appropriately
import org.slf4j.Logger; // Added for logging
import org.slf4j.LoggerFactory; // Added for logging
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional; // Import Transactional

@Repository
public class TokenRepository {

    private static final Logger log = LoggerFactory.getLogger(TokenRepository.class); // Added logger

    private static final int UPDATED_ROWS_COUNT = 1;
    private static final String NO = "N";
    private static final String YES = "Y"; // Define YES for clarity

    // SQL Statements
    private static final String INSERT_TOKEN = "INSERT INTO eg_token(id, tenantid, tokennumber, tokenidentity, validated, ttlsecs, createddate, createdby, version, createddatenew) VALUES (:id, :tenantId, :tokenNumber, :tokenIdentity, :validated, :ttlSecs, :createdDate, :createdBy, :version, :createddatenew)";
    // Expire previous *unvalidated* tokens for the same identity and tenant by setting TTL to 0
    private static final String EXPIRE_PREVIOUS_TOKENS = "UPDATE eg_token SET ttlsecs = 0 WHERE tenantid = :tenantId AND tokenidentity = :tokenIdentity AND validated = :validatedStatus";
    private static final String GET_VALID_TOKENS_BY_IDENTITY_TENANT = "SELECT * FROM eg_token WHERE tokenidentity = :tokenIdentity AND tenantid = :tenantId AND ((extract(epoch from now()) * 1000 - createddatenew) / 1000)::int <= ttlsecs AND validated = 'N'";
    private static final String UPDATE_TOKEN_AS_VALIDATED = "UPDATE eg_token SET validated = :validatedStatus WHERE id = :id";
    private static final String GET_TOKEN_BY_ID = "SELECT * FROM eg_token WHERE id = :id";
    // Renamed for clarity, functionality remains the same - resets the TTL from 'now'
    private static final String RESET_TOKEN_TTL_BY_ID = "UPDATE eg_token SET ttlsecs = (extract (epoch from now()) - createddatenew / 1000)::int + :ttl WHERE id = :id";


    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    @Autowired(required = false) // Make optional if OtpConfiguration might not always be present
    private OtpConfiguration otpConfiguration;

    // Constructor injection is generally preferred
    @Autowired
    public TokenRepository(NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        this.namedParameterJdbcTemplate = namedParameterJdbcTemplate;
    }

    /**
     * Saves a new token and expires previously generated, unvalidated tokens
     * for the same identity and tenant.
     * Ensure the calling service method is annotated with @Transactional.
     *
     * @param token The new token to save.
     * @return The saved token.
     */
    @Transactional // Add transactional annotation (or ensure service layer has it)
    public Token save(Token token) {
        // 1. Expire previous unvalidated tokens for this identity/tenant
        try {
            final Map<String, Object> expireParams = new HashMap<>();
            expireParams.put("tenantId", token.getTenantId());
            expireParams.put("tokenIdentity", token.getIdentity());
            expireParams.put("validatedStatus", NO); // Expire only non-validated tokens

            int expiredCount = namedParameterJdbcTemplate.update(EXPIRE_PREVIOUS_TOKENS, expireParams);
            if (expiredCount > 0) {
                log.info("Expired {} previous unvalidated token(s) for identity: {} and tenant: {}",
                        expiredCount, token.getIdentity(), token.getTenantId());
            }
        } catch (Exception e) {
            // Log the error but proceed to insert the new token.
            // Depending on requirements, you might want to re-throw or handle differently.
            log.error("Error expiring previous tokens for identity: {} and tenant: {}. Proceeding with new token insertion.",
                    token.getIdentity(), token.getTenantId(), e);
            // Consider if this failure should prevent the new token generation.
            // If yes, re-throw a specific exception here.
        }

        // 2. Insert the new token
        final Map<String, Object> tokenInputs = new HashMap<>();
        Date createdDate = new Date(); // Consider using Instant or LocalDateTime if possible
        tokenInputs.put("id", token.getUuid());
        tokenInputs.put("tenantId", token.getTenantId());
        tokenInputs.put("tokenNumber", token.getNumber());
        tokenInputs.put("tokenIdentity", token.getIdentity());
        tokenInputs.put("validated", NO); // New token is initially not validated
        tokenInputs.put("ttlSecs", token.getTimeToLiveInSeconds());
        tokenInputs.put("createdDate", createdDate); // This column might be redundant if createddatenew is used consistently
        tokenInputs.put("createdBy", 0L); // Use L for long literal
        tokenInputs.put("version", 0L);   // Use L for long literal
        tokenInputs.put("createddatenew", System.currentTimeMillis()); // Store as epoch milliseconds

        namedParameterJdbcTemplate.update(INSERT_TOKEN, tokenInputs);
        log.info("Saved new token with id: {} for identity: {}", token.getUuid(), token.getIdentity());

        return token;
    }

    /**
     * Marks a specific token as validated.
     *
     * @param token The token to mark as validated.
     * @return The updated token.
     * @throws TokenUpdateException if the update fails.
     */
    @Transactional // Add transactional annotation
    public Token markAsValidated(Token token) {
        token.setValidated(true); // Update the domain object state
        final boolean isUpdateSuccessful = markTokenAsValidatedInDb(token.getUuid()) == UPDATED_ROWS_COUNT;
        if (!isUpdateSuccessful) {
            log.error("Failed to mark token as validated in DB for id: {}", token.getUuid());
            throw new TokenUpdateException(token);
        }
        log.info("Marked token as validated for id: {}", token.getUuid());
        return token;
    }

    // Renamed for clarity (DB operation)
    private int markTokenAsValidatedInDb(String id) {
        final Map<String, Object> tokenInputs = new HashMap<>();
        tokenInputs.put("id", id);
        tokenInputs.put("validatedStatus", YES); // Use constant
        return namedParameterJdbcTemplate.update(UPDATE_TOKEN_AS_VALIDATED, tokenInputs);
    }

    /**
     * Finds currently valid (not expired, not validated) tokens for a given identity and tenant.
     *
     * @param request The request containing identity and tenantId.
     * @return A Tokens object containing a list of matching tokens.
     */
    public Tokens findValidTokensByIdentityAndTenant(ValidateRequest request) {
        final Map<String, Object> tokenInputs = new HashMap<>();
        tokenInputs.put("tokenIdentity", request.getIdentity());
        tokenInputs.put("tenantId", request.getTenantId());

        List<Token> domainTokens = namedParameterJdbcTemplate.query(
                GET_VALID_TOKENS_BY_IDENTITY_TENANT, // Use the correct query name
                tokenInputs,
                new TokenRowMapper());

        log.debug("Found {} valid tokens for identity: {} and tenant: {}",
                domainTokens.size(), request.getIdentity(), request.getTenantId());

        return new Tokens(domainTokens);
    }


    /**
     * Finds a token by its unique ID (UUID).
     *
     * @param searchCriteria Criteria containing the UUID.
     * @return The found Token, or null if not found.
     */
    public Token findBy(TokenSearchCriteria searchCriteria) {
        Token token = null;
        final Map<String, Object> tokenInputs = new HashMap<>();
        tokenInputs.put("id", searchCriteria.getUuid());

        List<Token> domainTokens = namedParameterJdbcTemplate.query(
                GET_TOKEN_BY_ID, // Use the correct query name
                tokenInputs,
                new TokenRowMapper());

        if (domainTokens != null && !domainTokens.isEmpty()) {
            token = domainTokens.get(0);
            log.debug("Found token by id: {}", searchCriteria.getUuid());
        } else {
            log.debug("Token not found for id: {}", searchCriteria.getUuid());
        }
        return token;
    }

    /**
     * Updates the TTL of a token, extending its validity from the current time.
     * Requires OtpConfiguration to be autowired.
     *
     * @param t The token whose TTL needs to be updated.
     * @return The number of rows affected (should be 1 if successful).
     */
    @Transactional // Add transactional annotation
    public int updateTTL(Token t) {
        if (otpConfiguration == null) {
            log.error("OtpConfiguration not wired, cannot update TTL for token id: {}", t.getUuid());
            // Depending on requirements, either return 0/error or throw an exception
            throw new IllegalStateException("OtpConfiguration is required to update TTL but is not available.");
        }
        final Map<String, Object> tokenInputs = new HashMap<>();
        tokenInputs.put("id", t.getUuid());
        tokenInputs.put("ttl", otpConfiguration.getTtl()); // Get TTL from config

        int updatedRows = namedParameterJdbcTemplate.update(RESET_TOKEN_TTL_BY_ID, tokenInputs);
        if (updatedRows == 1) {
            log.info("Successfully updated TTL for token id: {}", t.getUuid());
        } else {
            log.warn("Failed to update TTL or token not found for id: {}", t.getUuid());
        }
        return updatedRows;
    }

    // Setter injection for OtpConfiguration if needed (Autowired on field is more common)
    @Autowired(required = false)
    public void setOtpConfiguration(OtpConfiguration otpConfiguration) {
        this.otpConfiguration = otpConfiguration;
    }
}
