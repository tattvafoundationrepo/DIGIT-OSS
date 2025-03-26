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
import org.egov.web.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class TokenRepository {

    private static final int UPDATED_ROWS_COUNT = 1;
    private static final String NO = "N";
    private static final String YES = "Y";
    
    private static final String INSERT_TOKEN = "insert into eg_token(id,tenantid,tokennumber,tokenidentity,validated,ttlsecs,createddate,createdby,version,createddatenew) values (:id,:tenantId,:tokenNumber,:tokenIdentity,:validated,:ttlSecs,:createdDate,:createdBy,:version,:createddatenew);";
    
    private static final String EXPIRE_OLD_TOKENS = "update eg_token set validated = 'Y' where tokenidentity = :tokenIdentity and tenantid = :tenantId and validated = 'N'";
    
    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    @Autowired
    private OtpConfiguration otpConfiguration;

    public TokenRepository(NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        this.namedParameterJdbcTemplate = namedParameterJdbcTemplate;
    }

    public Token save(Token token) {
        final Map<String, Object> tokenInputs = new HashMap<>();
        Date createdDate = new Date();

        // Expire old tokens before inserting a new one
        expireOldTokens(token.getIdentity(), token.getTenantId());

        tokenInputs.put("id", token.getUuid());
        tokenInputs.put("tenantId", token.getTenantId());
        tokenInputs.put("tokenNumber", token.getNumber());
        tokenInputs.put("tokenIdentity", token.getIdentity());
        tokenInputs.put("validated", NO);
        tokenInputs.put("ttlSecs", token.getTimeToLiveInSeconds());
        tokenInputs.put("createdDate", createdDate);
        tokenInputs.put("createdBy", 0L);
        tokenInputs.put("version", 0L);
        tokenInputs.put("createddatenew", System.currentTimeMillis());

        namedParameterJdbcTemplate.update(INSERT_TOKEN, tokenInputs);
        return token;
    }

    private void expireOldTokens(String tokenIdentity, String tenantId) {
        final Map<String, Object> params = new HashMap<>();
        params.put("tokenIdentity", tokenIdentity);
        params.put("tenantId", tenantId);
        namedParameterJdbcTemplate.update(EXPIRE_OLD_TOKENS, params);
    }
}
