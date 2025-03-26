package org.egov.web.contract;



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
public class WebSecurityConfig {

    @Bean
    public FilterRegistrationBean<ResponseHeaderFilter> responseHeaderFilter() {
        FilterRegistrationBean<ResponseHeaderFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new ResponseHeaderFilter());
        registrationBean.addUrlPatterns("/v1/_send"); 
        registrationBean.setOrder(1); 
        return registrationBean;
    }
}
