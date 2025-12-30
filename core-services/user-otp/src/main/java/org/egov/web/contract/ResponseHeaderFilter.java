import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

public class ResponseHeaderFilter implements Filter {

    // Enhanced regex pattern to match all variations of OTP and rate-limit headers with IPs
    private static final Pattern IP_HEADER_PATTERN = Pattern.compile(
        ".*(user-otp|rate-limit).*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*",
        Pattern.CASE_INSENSITIVE
    );
    
    // Common sensitive headers that should be removed
    private static final Set<String> SENSITIVE_HEADERS = new HashSet<>(Arrays.asList(
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Runtime", "X-Request-ID", "X-Forwarded-For", "X-Forwarded-Host",
        "X-Forwarded-Proto", "X-Original-URL", "X-Rewrite-URL"
    ));

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            
            // Remove existing sensitive headers first
            SENSITIVE_HEADERS.forEach(header -> httpResponse.setHeader(header, null));

            // Wrap the response to filter headers
            HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(httpResponse) {
                @Override
                public void setHeader(String name, String value) {
                    if (!isSensitiveHeader(name)) {
                        super.setHeader(name, value);
                    }
                }

                @Override
                public void addHeader(String name, String value) {
                    if (!isSensitiveHeader(name)) {
                        super.addHeader(name, value);
                    }
                }

                @Override
                public void setIntHeader(String name, int value) {
                    if (!isSensitiveHeader(name)) {
                        super.setIntHeader(name, value);
                    }
                }

                @Override
                public void addIntHeader(String name, int value) {
                    if (!isSensitiveHeader(name)) {
                        super.addIntHeader(name, value);
                    }
                }

                @Override
                public void setDateHeader(String name, long date) {
                    if (!isSensitiveHeader(name)) {
                        super.setDateHeader(name, date);
                    }
                }

                @Override
                public void addDateHeader(String name, long date) {
                    if (!isSensitiveHeader(name)) {
                        super.addDateHeader(name, date);
                    }
                }

                private boolean isSensitiveHeader(String headerName) {
                    if (headerName == null) return false;
                    String lowerHeader = headerName.toLowerCase();
                    
                    // Check if header is in our sensitive list
                    if (SENSITIVE_HEADERS.contains(headerName)) {
                        return true;
                    }
                    
                    // Check for OTP or rate-limit headers containing IP addresses
                    return IP_HEADER_PATTERN.matcher(lowerHeader).matches();
                }
            };

            chain.doFilter(request, responseWrapper);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // You could load additional sensitive headers from configuration here
        String additionalHeaders = filterConfig.getInitParameter("sensitiveHeaders");
        if (additionalHeaders != null) {
            SENSITIVE_HEADERS.addAll(Arrays.asList(additionalHeaders.split(",")));
        }
    }

    @Override
    public void destroy() {
        // Cleanup if needed
    }
}
