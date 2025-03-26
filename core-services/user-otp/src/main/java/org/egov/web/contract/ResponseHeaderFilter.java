package org.egov.web.contract;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ResponseHeaderFilter implements Filter {

    // Regex pattern to match headers with an IP (IPv4 format)
    private static final Pattern IP_HEADER_PATTERN = Pattern.compile(".*_Otp_.*_(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            // Wrap the response to filter headers
            HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(httpResponse) {
                @Override
                public void setHeader(String name, String value) {
                    if (!IP_HEADER_PATTERN.matcher(name).matches()) {
                        super.setHeader(name, value);
                    }
                }

                @Override
                public void addHeader(String name, String value) {
                    if (!IP_HEADER_PATTERN.matcher(name).matches()) {
                        super.addHeader(name, value);
                    }
                }
            };

            chain.doFilter(request, responseWrapper);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization required
    }

    @Override
    public void destroy() {
        // Cleanup if needed
    }
}
