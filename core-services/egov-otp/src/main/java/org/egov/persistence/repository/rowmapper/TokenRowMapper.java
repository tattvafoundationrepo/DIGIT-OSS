package org.egov.persistence.repository.rowmapper;

import java.sql.ResultSet;package org.egov.persistence.repository.rowmapper; // Or your actual package

import org.egov.domain.model.Token;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component; // Or define as bean elsewhere

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp; // Import if using timestamp

// Assuming you have a Token.builder() or similar
@Component // If managed by Spring
public class TokenRowMapper implements RowMapper<Token> {

    @Override
    public Token mapRow(ResultSet rs, int rowNum) throws SQLException {
        Token.TokenBuilder tokenBuilder = Token.builder();

        // --- Apply .trim() here ---
        String id = rs.getString("id");
        String tenantId = rs.getString("tenantid");
        String identity = rs.getString("tokenidentity");
        String number = rs.getString("tokennumber"); // This is often the OTP itself

        tokenBuilder.uuid(id != null ? id.trim() : null);
        tokenBuilder.tenantId(tenantId != null ? tenantId.trim() : null);
        tokenBuilder.identity(identity != null ? identity.trim() : null);
        tokenBuilder.number(number != null ? number.trim() : null);
        // --- End of .trim() changes for Strings ---

        // Map other fields (Booleans, Numbers, Dates etc.)
        tokenBuilder.validated("Y".equalsIgnoreCase(rs.getString("validated"))); // Example boolean mapping

        // Be careful with Long vs Integer if the DB type changes
        Long ttlSecs = rs.getObject("ttlsecs", Long.class);
        tokenBuilder.timeToLiveInSeconds(ttlSecs);

        // Choose one date/time column based on what you actually use consistently
        Timestamp createdDateTimestamp = rs.getTimestamp("createddate");
        if (createdDateTimestamp != null) {
             // Convert Timestamp to Date if your model uses java.util.Date
             tokenBuilder.createdDate(new java.util.Date(createdDateTimestamp.getTime()));
        }

        // Or handle createddatenew (epoch millis)
        Long createdTimeEpoch = rs.getObject("createddatenew", Long.class);
         if (createdTimeEpoch != null) {
             tokenBuilder.createdTime(createdTimeEpoch); // Assuming a field 'createdTime' of type Long in Token model
             // If you still need the java.util.Date version from this:
             // tokenBuilder.createdDate(new java.util.Date(createdTimeEpoch));
         }

        // Map version if needed (often Long)
        Long version = rs.getObject("version", Long.class);
        if(version != null){
           // Add .version(version) to builder if the field exists
        }

        // Map createdby if needed (often Long)
         Long createdBy = rs.getObject("createdby", Long.class);
         if(createdBy != null){
            // Add .createdBy(createdBy) to builder if the field exists
         }


        return tokenBuilder.build();
    }
}
import java.sql.SQLException;

import org.egov.domain.model.Token;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

@Component
public class TokenRowMapper implements RowMapper<Token> {

    private static final String YES = "Y";

    @Override
    public Token mapRow(final ResultSet rs, final int rowNum) throws SQLException {

        Token token = Token.builder().uuid(rs.getString("id")).identity(rs.getString("tokenidentity"))
                .timeToLiveInSeconds(rs.getLong("ttlsecs")).number(rs.getString("tokennumber")).createdDate(rs.getDate("createddate"))
                .tenantId(rs.getString("tenantid")).createdTime(rs.getLong("createddatenew")).build();
        token.setValidated(isValidated(rs.getString("validated")));

        return token;
    }

    public boolean isValidated(String validated) {
        return YES.equalsIgnoreCase(validated);
    }

}
