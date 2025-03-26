package org.egov.domain.service;

import static org.apache.commons.lang3.RandomStringUtils.randomNumeric;

import java.util.UUID;

import org.egov.domain.exception.TokenValidationFailureException;
import org.egov.domain.model.Token;
import org.egov.domain.model.TokenRequest;
import org.egov.domain.model.TokenSearchCriteria;
import org.egov.domain.model.Tokens; // Ensure this import is correct
import org.egov.domain.model.ValidateRequest;
import org.egov.persistence.repository.TokenRepository;
import org.egov.web.util.OtpConfiguration; // Ensure this import is correct
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Import Transactional

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j // Lombok annotation for logging
public class TokenService {

    private final TokenRepository tokenRepository; // Mark as final if using constructor injection
    private final OtpConfiguration otpConfiguration; // Mark as final
    private final PasswordEncoder passwordEncoder; // Mark as final

    @Autowired
    public TokenService(TokenRepository tokenRepository, PasswordEncoder passwordEncoder, OtpConfiguration otpConfiguration) {
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpConfiguration = otpConfiguration;
    }

    /**
     * Creates a new OTP token, saves it, and expires previous tokens for the identity.
     * This operation is transactional.
     *
     * @param tokenRequest Details of the token request.
     * @return The created Token with the original (unencrypted) OTP number.
     */
    @Transactional // Ensure atomicity (expire old tokens + save new one)
    public Token create(TokenRequest tokenRequest) {
        log.debug("Creating token for identity: {}", tokenRequest.getIdentity());
        tokenRequest.validate();

        String originalOtp = randomNumeric(otpConfiguration.getOtpLength());
        String encryptedOtp = originalOtp;

        // Encrypt if configured
        if (otpConfiguration.isEncryptOTP()) {
            log.debug("Encrypting OTP for identity: {}", tokenRequest.getIdentity());
            encryptedOtp = passwordEncoder.encode(originalOtp);
        }

        // Build the token for persistence
        Token token = Token.builder()
                .uuid(UUID.randomUUID().toString())
                .tenantId(tokenRequest.getTenantId())
                .identity(tokenRequest.getIdentity())
                .number(encryptedOtp) // Store encrypted OTP in DB
                .timeToLiveInSeconds(otpConfiguration.getTtl())
                .validated(false) // Explicitly set validated to false
                .build();

        // Save the token (this now also expires previous tokens in the repository method)
        token = tokenRepository.save(token);
        log.info("Successfully saved new token with id: {} for identity: {}", token.getUuid(), token.getIdentity());

        // Return the token object containing the ORIGINAL OTP for the user
        token.setNumber(originalOtp);
        return token;
    }

    /**
     * Validates an OTP against stored, valid tokens for the identity.
     * Marks the token as validated upon successful match.
     * This operation is transactional.
     *
     * @param validateRequest Details for validation (identity, tenant, OTP).
     * @return The validated Token.
     * @throws TokenValidationFailureException if no valid token is found or the OTP doesn't match.
     */
    @Transactional // Ensure atomicity (find + mark as validated)
    public Token validate(ValidateRequest validateRequest) {
        log.debug("Validating token for identity: {}", validateRequest.getIdentity());
        validateRequest.validate();

        // *** FIX 1: Use the renamed repository method ***
        Tokens tokens = tokenRepository.findValidTokensByIdentityAndTenant(validateRequest);

        if (tokens == null || tokens.getTokens().isEmpty()) {
            log.warn("No valid, unexpired tokens found for identity: {}", validateRequest.getIdentity());
            throw new TokenValidationFailureException();
        }

        log.debug("Found {} potentially valid token(s) for identity: {}", tokens.getTokens().size(), validateRequest.getIdentity());

        for (Token t : tokens.getTokens()) {
            // Check if OTP matches (plain or encrypted)
            boolean otpMatches = false;
            if (!otpConfiguration.isEncryptOTP() && validateRequest.getOtp().equalsIgnoreCase(t.getNumber())) {
                otpMatches = true; // Plain text match
                log.debug("Plain text OTP match found for token id: {}", t.getUuid());
            } else if (otpConfiguration.isEncryptOTP() && passwordEncoder.matches(validateRequest.getOtp(), t.getNumber())) {
                otpMatches = true; // Encrypted match
                log.debug("Encrypted OTP match found for token id: {}", t.getUuid());
            }

            if (otpMatches) {
                // *** FIX 2: Call the existing repository method (no rename needed here) ***
                Token validatedToken = tokenRepository.markAsValidated(t); // Marks in DB and returns updated obj
                log.info("Successfully validated token with id: {} for identity: {}", t.getUuid(), validateRequest.getIdentity());
                return validatedToken; // Return the token marked as validated
            }
        }

        // If loop completes without returning, no match was found
        log.warn("OTP validation failed for identity: {}. No matching OTP found among valid tokens.", validateRequest.getIdentity());
        throw new TokenValidationFailureException();
    }

    /**
     * Searches for a token by its unique UUID.
     * This operation is typically read-only.
     *
     * @param searchCriteria Criteria containing the UUID.
     * @return The found Token, or null if not found.
     */
    @Transactional(readOnly = true) // Mark as read-only transaction
    public Token search(TokenSearchCriteria searchCriteria) {
        log.debug("Searching for token with uuid: {}", searchCriteria.getUuid());
        // *** FIX 3: Call the existing repository method (no rename needed here) ***
        return tokenRepository.findBy(searchCriteria);
    }
}
