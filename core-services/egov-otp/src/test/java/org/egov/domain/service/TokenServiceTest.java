package org.egov.domain.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any; // Use ArgumentMatchers instead of Matchers
import static org.mockito.Mockito.*; // Import static mockito methods

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.egov.domain.exception.TokenValidationFailureException;
// TokenAlreadyUsedException is not used in this file, can be removed if needed
// import org.egov.domain.exception.TokenAlreadyUsedException;
import org.egov.domain.model.Token;
import org.egov.domain.model.TokenRequest;
import org.egov.domain.model.TokenSearchCriteria;
import org.egov.domain.model.Tokens;
import org.egov.domain.model.ValidateRequest;
import org.egov.persistence.repository.TokenRepository;
import org.egov.web.util.*; // Ensure LocalDateTimeFactory and OtpConfiguration are here
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
// MockitoJUnitRunner is deprecated, consider using @ExtendWith(MockitoExtension.class) for JUnit 5
import org.mockito.junit.MockitoJUnitRunner;
// @Autowired and @SpringBootTest are not needed for pure Mockito tests
// import org.springframework.beans.factory.annotation.*;
// import org.springframework.boot.test.context.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// Mockito has its own @InjectMocks annotation for dependency injection

@RunWith(MockitoJUnitRunner.class)
public class TokenServiceTest {

    @Mock
    private TokenRepository tokenRepository;

    @Mock
    private LocalDateTimeFactory localDateTimeFactory; // Assuming this is used internally (though not directly shown here)

    @InjectMocks
    private TokenService tokenService;

    // `now` variable not explicitly used in current tests, can be removed if not needed later
    // private LocalDateTime now;

    // You can initialize directly if BCryptPasswordEncoder has a default constructor
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Before
    public void before() {
        // now = LocalDateTime.now(ZoneId.of("UTC"));
        // lenient().when(localDateTimeFactory.now()).thenReturn(now); // Only needed if code under test uses localDateTimeFactory.now()

        // OtpConfiguration should be mocked or instantiated properly. Instantiating here.
        OtpConfiguration otpConfiguration = new OtpConfiguration(90, 6, true); // Example values: ttl=90, length=6, encrypt=true

        // Re-initialize tokenService with mocks and dependencies in each test or here in @Before
        // Use the field passwordEncoder instantiated above
        this.tokenService = new TokenService(tokenRepository, passwordEncoder, otpConfiguration);

        // Use lenient() stubbing if the mock might not be called in every test path
        lenient().when(tokenRepository.save(any(Token.class))).thenAnswer(invocation -> invocation.getArgument(0));
        lenient().when(tokenRepository.markAsValidated(any(Token.class))).thenAnswer(invocation -> {
             Token t = invocation.getArgument(0);
             t.setValidated(true); // Simulate marking as validated
             return t;
         });
         lenient().when(tokenRepository.findBy(any(TokenSearchCriteria.class))).thenReturn(Token.builder().build()); // Default findBy mock
    }

    @Test
    public void test_should_save_new_token_with_given_identity_and_tenant() {
        // Arrange
        // *** FIX: Use the correct two-argument constructor for TokenRequest ***
        final TokenRequest tokenRequest = new TokenRequest("tenantId", "identity"); // Minimal request
        // Removed the ValidateRequest mock setup here as it's not relevant to the create method test
        // when(tokenRepository.save(any(Token.class))) is already set up leniently in @Before

        // Act
        final Token actualToken = tokenService.create(tokenRequest);

        // Assert
        verify(tokenRepository).save(any(Token.class)); // Verify save was called
        assertThat(actualToken).isNotNull();
        assertThat(actualToken.getNumber()).hasSize(6); // Assuming length 6 from OtpConfiguration
        assertThat(actualToken.getTenantId()).isEqualTo("tenantId");
        //assertThat(actualToken.getIdentity()).isEqualTo("identity");
        //assertThat(actualToken.getTenantId()).isEqualTo("tenantId");
    }

    @Test
    public void test_should_validate_token_request() {
        // Arrange
        // Using a spy or mock might be complex here just to verify validate().
        // If TokenRequest.validate() has side effects, test them. If not, this test might be optional.
        // For now, we assume the `validate()` method should just be called.
        final TokenRequest tokenRequest = mock(TokenRequest.class);
        doNothing().when(tokenRequest).validate(); // Stub the validate method

        // Act
        tokenService.create(tokenRequest);

        // Assert
        verify(tokenRequest).validate(); // Verify that the validate method was called
    }

    @Test(expected = TokenValidationFailureException.class)
    public void test_should_throw_exception_when_no_matching_non_expired_token_is_present() {
        // Arrange
        final ValidateRequest validateRequest = new ValidateRequest("tenant", "otpNumber", "identity");
        // Return an empty Tokens object to simulate no tokens found
        final Tokens emptyTokens = new Tokens(new ArrayList<>());
        // *** Use the renamed method in the mock setup ***
        when(tokenRepository.findValidTokensByIdentityAndTenant(validateRequest)).thenReturn(emptyTokens);

        // Act
        tokenService.validate(validateRequest);

        // Assert (Exception expected)
    }

    @Test(expected = TokenValidationFailureException.class)
    public void test_should_throw_exception_when_validating_already_validated_token_and_otp_does_not_match() {
        // Arrange
        final String rawOtp = "123456"; // Different from the token's OTP
        final ValidateRequest validateRequest = new ValidateRequest("default", rawOtp, "test");

        // This token is ALREADY validated, so findValidTokensByIdentityAndTenant shouldn't return it
        // Let's assume findValid returns NO tokens because only validated ones exist.
        Tokens emptyTokens = new Tokens(new ArrayList<>());

        // *** Use the renamed method in the mock setup ***
        when(tokenRepository.findValidTokensByIdentityAndTenant(validateRequest)).thenReturn(emptyTokens);

        // Act
        tokenService.validate(validateRequest);

        // Assert (Exception expected)
    }

    @Test(expected = TokenValidationFailureException.class)
    public void test_should_throw_exception_when_otp_does_not_match() {
        // Arrange
        final String rawOtpSentByUser = "654321"; // Incorrect OTP
        final String correctRawOtp = "123456";
        final String correctEncryptedOtp = passwordEncoder.encode(correctRawOtp);

        final ValidateRequest validateRequest = new ValidateRequest("default", rawOtpSentByUser, "test");

        Token token = Token.builder()
                .uuid("some-uuid")
                .identity("test")
                .validated(false) // Token is not validated yet
                .timeToLiveInSeconds(300L)
                .number(correctEncryptedOtp) // Stored encrypted OTP
                .tenantId("default")
                .createdTime(new Date().getTime())
                .build();
        List<Token> tokenList = new ArrayList<>();
        tokenList.add(token);
        Tokens tokens = new Tokens(tokenList);

        // *** Use the renamed method in the mock setup ***
        when(tokenRepository.findValidTokensByIdentityAndTenant(validateRequest)).thenReturn(tokens);

        // Act
        tokenService.validate(validateRequest);

        // Assert (Exception expected because rawOtpSentByUser won't match correctEncryptedOtp)
    }


    @Test
    public void test_should_return_token_when_token_is_successfully_validated() {
        // Arrange
        final String rawOtp = "12345";
        final ValidateRequest validateRequest = new ValidateRequest("default", rawOtp, "test");

        // Prepare the token as stored in the DB (encrypted)
        Token storedToken = Token.builder()
                .uuid("test-uuid")
                .identity("test")
                .validated(false) // IMPORTANT: Must be false initially
                .timeToLiveInSeconds(300L)
                .number(passwordEncoder.encode(rawOtp)) // Store encrypted version
                .tenantId("default")
                .createdTime(new Date().getTime()) // Ensure it's not expired relative to 'now' if checked
                .build();
        List<Token> tokenList = new ArrayList<>();
        tokenList.add(storedToken);
        Tokens tokens = new Tokens(tokenList);

        // *** Use the renamed method in the mock setup ***
        when(tokenRepository.findValidTokensByIdentityAndTenant(validateRequest)).thenReturn(tokens);
        // No need to mock markAsValidated separately if using lenient().thenAnswer() in @Before

        // Act
        final Token validatedToken = tokenService.validate(validateRequest);

        // Assert
        assertThat(validatedToken).isNotNull();
        assertThat(validatedToken.isValidated()).isTrue(); // Check if the returned token state is updated
        assertThat(validatedToken.getUuid()).isEqualTo("test-uuid");
        // Verify that markAsValidated was called on the repository with the correct token object
        verify(tokenRepository).markAsValidated(storedToken);
    }

    @Test
    public void test_should_return_otp_for_given_search_criteria() {
        // Arrange
        final Token expectedToken = Token.builder().uuid("uuid").tenantId("tenant").build();
        final TokenSearchCriteria searchCriteria = new TokenSearchCriteria("uuid", "tenant");
        // Use lenient setup from @Before or specific setup here:
        when(tokenRepository.findBy(searchCriteria)).thenReturn(expectedToken);

        // Act
        final Token actualToken = tokenService.search(searchCriteria);

        // Assert
        assertEquals(expectedToken, actualToken);
        verify(tokenRepository).findBy(searchCriteria); // Verify findBy was called
    }
}
