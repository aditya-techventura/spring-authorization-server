package org.example.secure.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Component
@Order
@Slf4j
public class OAuth2ClientBackendMappingFilter implements Filter {

	@Value("${clientResolver.headers}")
	List<String> clientResolverHeaders;

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;

		List<String> clientBackendContext = new ArrayList<>();
		Iterator<String> headerNames = request.getHeaderNames().asIterator();
		while (headerNames.hasNext()) {
			String headerName = headerNames.next().toLowerCase();
			if (clientResolverHeaders.stream().anyMatch(headerName::equalsIgnoreCase)) {
				String headerValue = request.getHeader(headerName);
				if (StringUtils.hasText(headerValue)) {
					clientBackendContext.add(headerValue);
				} else {
					// TODO: Should be a BadRequest
					throw new IllegalStateException("Invalid Request! Expected " + headerName + " is not present");
				}
			}
		}
		if (!clientBackendContext.isEmpty()) {
			ClientBackEndMappingContextHolder.set(String.join("-", clientBackendContext).toLowerCase());
			log.info("Setting the clientBackEndMappingContextHolder: {}", ClientBackEndMappingContextHolder.getClientBackendMappingContext());
		}

		try {
			filterChain.doFilter(servletRequest, servletResponse);
		} finally {
			ClientBackEndMappingContextHolder.clear();
		}
	}
}
