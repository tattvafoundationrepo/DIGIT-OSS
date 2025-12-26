package org.egov.web.notification.mail.consumer.contract;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EmailAttachment {
    
    @JsonProperty("name")
    private String name; 
    
    @JsonProperty("mimeType")
    private String mimeType; 
    
    @JsonProperty("data")
    private String data;
}
