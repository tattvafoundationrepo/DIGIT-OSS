package org.egov.persistence.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Date;
import java.util.UUID;
import java.util.List; // Import List

import org.egov.domain.exception.TokenUpdateException;
import org.egov.domain.model.Token;
import org.egov.domain.model.TokenSearchCriteria;
import org.egov.domain.model.Tokens;
import org.egov.domain.model.ValidateRequest;
import org.egov.web.util.OtpConfiguration; // Import if needed for updateTTL tests later
import org.junit.*;
import org.junit.runner.RunWith;
// InjectMocks is for Mockito, not Spring Boot tests
// import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional; // Add for transactional tests


@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Transactional // Make tests transactional to rollback changes automatically
public class TokenRepositoryTest {

    // Use @Autowired for Spring Boot integration tests
    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate; // Can still autowire this if needed

    // @Before might not be strictly necessary if @Autowired works directly
    // @Before
    // public void before() {
    //     // The repository bean should already be created by Spring context
    //     // tokenRepository = new TokenRepository(namedParameterJdbcTemplate);
    // }

    @Test
    @Sql(scripts = {"/sql/clearTokens.sql"}) // Clear before test
    public void test_save_should_insert_new_token() {
        // Arrange
        final Token token = Token.builder()
                .uuid(UUID.randomUUID().toString())
                .number("99999")
                .identity("someIdentity")
                .timeToLiveInSeconds(400L) // Use L for long
                .createdDate(new Date())   // Note: createdDate might be redundant if createddatenew is primary
                .tenantId("test-tenant")
                .validated(false) // Explicitly set
                .build();

        // Act
        Token savedToken = tokenRepository.save(token);

        // Assert using findBy to verify persistence
        Token fetchedToken = tokenRepository.findBy(new TokenSearchCriteria(savedToken.getUuid(), savedToken.getTenantId()));

        assertNotNull(fetchedToken);
        assertEquals(token.getTenantId(), fetchedToken.getTenantId());
        assertEquals(token.getUuid(), fetchedToken.getUuid());
        assertEquals(token.getIdentity(), fetchedToken.getIdentity());
        assertEquals(token.getNumber(), fetchedToken.getNumber()); // Assumes OTP encryption is off or tested elsewhere
        assertEquals(token.getTimeToLiveInSeconds(), fetchedToken.getTimeToLiveInSeconds());
        assertFalse(fetchedToken.isValidated()); // Should be saved as false
    }

    @Test
    @Sql(scripts = {"/sql/clearTokens.sql"}) // Clear before test
    public void test_save_should_expire_previous_unvalidated_tokens() {
        // Arrange: Save an initial token
        String identity = "expiring-identity";
        String tenantId = "test-tenant";
        Token initialToken = Token.builder()
                .uuid(UUID.randomUUID().toString())
                .number("11111")
                .identity(identity)
                .timeToLiveInSeconds(300L)
                .tenantId(tenantId)
                .validated(false)
                .build();
        tokenRepository.save(initialToken); // Save initial

        // Verify initial token is findable and valid (TTL > 0)
        Tokens initialTokensFound = tokenRepository.findValidTokensByIdentityAndTenant(
            ValidateRequest.builder().identity(identity).tenantId(tenantId).build()
        );
        assertNotNull(initialTokensFound);
        assertEquals(1, initialTokensFound.getTokens().size());
        assertTrue(initialTokensFound.getTokens().get(0).getTimeToLiveInSeconds() > 0);


        // Act: Save a NEW token for the same identity/tenant
        Token newToken = Token.builder()
                .uuid(UUID.randomUUID().toString())
                .number("22222")
                .identity(identity)
                .timeToLiveInSeconds(400L)
                .tenantId(tenantId)
                .validated(false)
                .build();
        tokenRepository.save(newToken); // Save new one, triggering expiry of 'initialToken'

        // Assert:
        // 1. Check if the NEW token is present and valid
        Tokens currentTokensFound = tokenRepository.findValidTokensByIdentityAndTenant(
            ValidateRequest.builder().identity(identity).tenantId(tenantId).build()
        );
        assertNotNull(currentTokensFound);
        assertEquals(1, currentTokensFound.getTokens().size()); // Only the new token should be found by findValid...
        assertEquals(newToken.getUuid(), currentTokensFound.getTokens().get(0).getUuid());
        assertEquals(400L, currentTokensFound.getTokens().get(0).getTimeToLiveInSeconds().longValue());


        // 2. Verify the INITIAL token is no longer found by findValidTokensByIdentityAndTenant
        //    (implicitly checked above) OR explicitly check its TTL is now 0
        Token fetchedInitialToken = tokenRepository.findBy(new TokenSearchCriteria(initialToken.getUuid(), tenantId));
        assertNotNull(fetchedInitialToken);
        assertEquals(0L, fetchedInitialToken.getTimeToLiveInSeconds().longValue()); // TTL should be 0 (expired)
        assertFalse(fetchedInitialToken.isValidated()); // Still not validated

    }


    @Test
    // *** This test was marked @Ignore ***
    @Ignore
    @Sql(scripts = {"/sql/clearTokens.sql", "/sql/createTokens.sql"})
    public void test_should_retrieve_otp_for_given_token_number_and_identity() {
        // Arrange
        // Assuming /sql/createTokens.sql creates an unvalidated, unexpired token:
        // id='id2', identity='identity2', tenantid='tenant2', tokennumber='token2', ttlsecs=200, validated='N'
        ValidateRequest validateRequest = ValidateRequest.builder()
                .otp("token2") // This is confusing, ValidateRequest OTP is for matching, not querying by number
                .identity("identity2")
                .tenantId("tenant2")
                .build();

        // Act
        // *** FIX 1: Use the renamed method ***
        final Tokens actualTokens = tokenRepository.findValidTokensByIdentityAndTenant(validateRequest);

        // Assert
        assertNotNull("Tokens object should not be null", actualTokens);
        List<Token> foundList = actualTokens.getTokens();
        assertNotNull("Token list should not be null", foundList);
        assertEquals("Should find exactly one valid token", 1, foundList.size());

        final Token firstToken = foundList.get(0);
        assertEquals("id2", firstToken.getUuid());
        assertEquals("identity2", firstToken.getIdentity());
        assertEquals("tenant2", firstToken.getTenantId());
        assertEquals("token2", firstToken.getNumber()); // Assumes token number matches OTP for this test's setup
        assertEquals(Long.valueOf(200), firstToken.getTimeToLiveInSeconds());
        assertFalse(firstToken.isValidated());
        assertNotNull(firstToken.getCreatedDate()); // Or createddatenew depending on row mapper
    }

    @Test
    @Sql(scripts = {"/sql/clearTokens.sql", "/sql/createTokens.sql"})
    public void test_findBy_should_fetch_token_by_id() {
        // Arrange: Assuming /sql/createTokens.sql creates token with id='id1', tenantid='tenant1'
        TokenSearchCriteria searchCriteria = new TokenSearchCriteria("id1", "tenant1");

        // Act
        final Token token = tokenRepository.findBy(searchCriteria);

        // Assert
        assertNotNull(token);
        assertEquals("id1", token.getUuid());
        assertEquals("tenant1", token.getTenantId());
        // Add more assertions based on expected data in createTokens.sql for id1
        // e.g., assertTrue(token.isValidated()); // Assuming id1 is marked 'Y' in the SQL
    }

    @Test
    @Sql(scripts = {"/sql/clearTokens.sql", "/sql/createTokens.sql"})
    public void test_findBy_should_return_null_when_token_not_present_for_given_id() {
        // Arrange
        TokenSearchCriteria searchCriteria = new TokenSearchCriteria("id_that_does_not_exist", "tenant_NA");

        // Act
        final Token token = tokenRepository.findBy(searchCriteria);

        // Assert
        assertNull(token);
    }

    @Test
    @Sql(scripts = {"/sql/clearTokens.sql", "/sql/createTokens.sql"})
    public void test_markAsValidated_should_update_token_status() {
        // Arrange: Select an unvalidated token from the SQL setup
        // Assuming /sql/createTokens.sql has id='id2', tenantid='tenant2', validated='N'
        String targetUuid = "id2";
        String targetTenant = "tenant2";
        TokenSearchCriteria searchCriteria = new TokenSearchCriteria(targetUuid, targetTenant);

        // Ensure it's initially not validated
        Token initialToken = tokenRepository.findBy(searchCriteria);
        assertNotNull(initialToken);
        assertFalse(initialToken.isValidated());

        // Create a token object to pass to markAsValidated (only needs ID)
        final Token tokenToValidate = Token.builder().uuid(targetUuid).build();

        // Act
        Token resultToken = tokenRepository.markAsValidated(tokenToValidate);

        // Assert
        // 1. Check the returned token object
        assertNotNull(resultToken);
        assertTrue("Returned token object should be marked validated", resultToken.isValidated());
        assertEquals(targetUuid, resultToken.getUuid());

        // 2. Verify by fetching the token again from DB
        Token fetchedToken = tokenRepository.findBy(searchCriteria);
        assertNotNull("Token should still exist after update", fetchedToken);
        assertTrue("Token in DB should now be validated", fetchedToken.isValidated());
    }

    @Test(expected = TokenUpdateException.class)
    @Sql(scripts = {"/sql/clearTokens.sql"}) // Ensure no token exists
    public void test_markAsValidated_should_throw_exception_when_token_does_not_exist() {
        // Arrange: A token that doesn't exist
        final Token nonExistentToken = Token.builder().uuid("uuid_that_does_not_exist").build();

        // Act
        tokenRepository.markAsValidated(nonExistentToken); // This should fail to update any rows and throw

        // Assert (Exception expected)
    }
}
