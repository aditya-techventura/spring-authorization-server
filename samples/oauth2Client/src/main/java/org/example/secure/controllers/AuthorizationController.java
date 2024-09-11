package org.example.secure.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Iterator;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

@RestController
public class AuthorizationController {

	private final WebClient defaultClientWebClient;
	private final String messagesBaseUri;
	private final ObjectMapper objectMapper;

	public AuthorizationController(
			@Qualifier("default-client-web-client") WebClient defaultClientWebClient,
			@Value("${messages.base-uri}") String messagesBaseUri, ObjectMapper objectMapper) {
		this.defaultClientWebClient = defaultClientWebClient;
		this.messagesBaseUri = messagesBaseUri;
		this.objectMapper = objectMapper;
	}

	// '/authorized' is the registered 'redirect_uri' for authorization_code
	@GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
	public String authorizationFailed(Model model, HttpServletRequest request) {
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		if (StringUtils.hasText(errorCode)) {
			model.addAttribute("error",
					new OAuth2Error(
							errorCode,
							request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
							request.getParameter(OAuth2ParameterNames.ERROR_URI))
			);
		}
		return "index";
	}

	@GetMapping(value = "/authorize", params = {"grant_type=client_credentials", "client_auth=private_key_jwt"})
	public String clientCredentialsGrantUsingPrivateKeyJwt() throws JsonProcessingException {

		String[] messages = this.defaultClientWebClient
				.get()
				.uri(this.messagesBaseUri)
				.headers(httpHeaders -> httpHeaders.addAll(defaultHeaders()))
				.attributes(clientRegistrationId("private-key-jwt-messaging-client-client-credentials"))
				.retrieve()
				.bodyToMono(String[].class)
				.block();
		return objectMapper.writeValueAsString(messages);
	}

	@GetMapping(value = "/authorize", params = {"grant_type=client_credentials", "client_auth=mtls"})
	public String clientCredentialsGrantUsingMutualTLS() throws JsonProcessingException {

		String[] messages = this.defaultClientWebClient
				.get()
				.uri(this.messagesBaseUri)
				.attributes(clientRegistrationId("mtls-demo-client-client-credentials"))
				.retrieve()
				.bodyToMono(String[].class)
				.block();

		return objectMapper.writeValueAsString(messages) ;
	}


	public HttpHeaders defaultHeaders() {
		// TODO: This can be taken from the current Request or from a ThreadLocal Context
		HttpHeaders headers = new HttpHeaders();
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
		HttpServletRequest request = requestAttributes.getRequest();

		Iterator<String> requestHeaderName = request.getHeaderNames().asIterator();
		while(requestHeaderName.hasNext()){
			String headerName = requestHeaderName.next();
			headers.add(headerName, request.getHeader(headerName));
		}
		return headers;
	}

	@ExceptionHandler(WebClientResponseException.class)
	public String handleError(Model model, WebClientResponseException ex) {
		model.addAttribute("error", ex.getMessage());
		return "index";
	}

}
