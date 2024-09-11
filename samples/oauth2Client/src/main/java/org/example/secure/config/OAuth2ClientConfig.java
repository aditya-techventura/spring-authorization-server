package org.example.secure.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.example.secure.outh2.client.CustomOAuth2TokenRequestHeadersConverter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

@Configuration
public class OAuth2ClientConfig {

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		final JWKSet jwkSet = new JWKSet(generateRSAJwk());
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	public Function<ClientRegistration, JWK> jwkResolver(final JWKSource<SecurityContext> jwkSource) {
		final JWKSelector jwkSelector = new JWKSelector(new JWKMatcher.Builder().privateOnly(true).build());
		return (registration) -> {
			if (!registration.getClientId().equals("messaging-client")) {
				return null;
			}
			JWKSet jwkSet = null;
			try {
				jwkSet = new JWKSet(jwkSource.get(jwkSelector, null));
			} catch (Exception ex) { }
			return jwkSet != null ? jwkSet.getKeys().iterator().next() : null;
		};
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			//OAuth2AuthorizedClientRepository authorizedClientRepository,
			OAuth2AuthorizedClientService authorizedClientService,
			RestTemplateBuilder restTemplateBuilder,
			Function<ClientRegistration, JWK> jwkResolver,
			@Qualifier("default-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		// @formatter:off
		RestTemplate restTemplate = restTemplateBuilder
				.requestFactory(clientHttpRequestFactory)
				.messageConverters(Arrays.asList(
						new FormHttpMessageConverter(),
						new OAuth2AccessTokenResponseHttpMessageConverter()))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();
		// @formatter:on

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials(clientCredentials ->
								clientCredentials.accessTokenResponseClient(
										createClientCredentialsTokenResponseClient(restTemplate, jwkResolver)))
						//.provider(new OAuth2AuthorizedClientProviderImpl())
						.build();
		// @formatter:on

//		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
//				clientRegistrationRepository, authorizedClientRepository);
//		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}


	private static RSAKey generateRSAJwk() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}

		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		return new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
	}

	private static OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> createClientCredentialsTokenResponseClient(
			RestTemplate restTemplate, Function<ClientRegistration, JWK> jwkResolver) {

		DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
				new DefaultClientCredentialsTokenResponseClient();
		clientCredentialsTokenResponseClient.setRestOperations(restTemplate);

		CustomOAuth2TokenRequestHeadersConverter<OAuth2ClientCredentialsGrantRequest> customHeaders = new CustomOAuth2TokenRequestHeadersConverter<>();

		OAuth2ClientCredentialsGrantRequestEntityConverter clientCredentialsGrantRequestEntityConverter =
				new OAuth2ClientCredentialsGrantRequestEntityConverter();
		clientCredentialsGrantRequestEntityConverter.addHeadersConverter(customHeaders);

		clientCredentialsGrantRequestEntityConverter.addParametersConverter(
				new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
		clientCredentialsGrantRequestEntityConverter.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			// client_id parameter is required for tls_client_auth, private_key_jwt and client_secret_jwt
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});
		clientCredentialsTokenResponseClient.setRequestEntityConverter(clientCredentialsGrantRequestEntityConverter);

		return clientCredentialsTokenResponseClient;
	}
}
