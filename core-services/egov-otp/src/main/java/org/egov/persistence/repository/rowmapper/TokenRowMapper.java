package org.egov.persistence.repository.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp; // Ensure this import is correct and clean

import org.egov.domain.model.Token;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

@Component
public class TokenRowMapper implements RowMapper<Token> { // Class definition starts here {

    private static final String YES = "Y";

    @Override
    public Token mapRow(final ResultSet rs, final int rowNum) throws SQLException { // mapRow method starts here {

        // --- Retrieve Strings ---
        String id = rs.getString("id");
        String identity = rs.getString("tokenidentity");
        String number = rs.getString("tokennumber");
        String tenantId = rs.getString("tenantid");
        String validatedStatus = rs.getString("validated"); // Retrieve status

        // --- Start Building Token ---
        Token.TokenBuilder tokenBuilder = Token.builder();

        // --- Use trimmed Strings (null-safe) ---
        tokenBuilder.uuid(id != null ? id.trim() : null);
        tokenBuilder.identity(identity != null ? identity.trim() : null);
        tokenBuilder.number(number != null ? number.trim() : null);
        tokenBuilder.tenantId(tenantId != null ? tenantId.trim() : null);

        // --- Map other fields ---
        tokenBuilder.timeToLiveInSeconds(rs.getLong("ttlsecs"));

        // Handle 'createddate' using Timestamp for precision
        Timestamp createdTimestamp = rs.getTimestamp("createddate");
        if (createdTimestamp != null) {
            tokenBuilder.createdDate(new java.util.Date(createdTimestamp.getTime())); // Convert Timestamp to util.Date
        }

        // Handle 'createddatenew' (assuming epoch millis for 'createdTime' field)
        Long createdTimeEpoch = rs.getObject("createddatenew", Long.class); // Use getObject for null safety
        if (createdTimeEpoch != null) {
             tokenBuilder.createdTime(createdTimeEpoch);
        }

        // Build the token object
        Token token = tokenBuilder.build();

        // Set validated status using the helper method
        token.setValidated(isValidated(validatedStatus));

        return token;

    } // mapRow method ends here }

    // Helper method to check validation status
    private boolean isValidated(String validatedDbValue) { // isValidated method starts here {
        return YES.equalsIgnoreCase(validatedDbValue);
    } // isValidated method ends here }

} // Class definition ends here }
// <<< MAKE ABSOLUTELY SURE THERE IS NOTHING AFTER THIS LINE >>>
