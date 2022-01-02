/*
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.util.Arrays;
import java.util.function.Supplier;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.SslProvider;
import sample.authorization.DeviceCodeOAuth2AuthorizedClientProvider;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.0.1
 */
@Configuration(proxyBeanMethods = false)
public class WebClientConfig {

	@Bean
	WebClient webClient(SslBundles sslBundles, OAuth2AuthorizedClientManager authorizedClientManager) throws Exception {
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

		SslContext sslContext = createSslContext(sslBundles);

		// @formatter:off
		return WebClient.builder()
				.clientConnector(createClientConnector(sslContext))
				.apply(oauth2Client.oauth2Configuration())
				.build();
		// @formatter:on
	}

	private static SslContext createSslContext(SslBundles sslBundles) throws Exception {
		SslBundle sslBundle = sslBundles.getBundle("demo-client");

		KeyManagerFactory keyManagerFactory = sslBundle.getManagers().getKeyManagerFactory();
		TrustManagerFactory trustManagerFactory = sslBundle.getManagers().getTrustManagerFactory();

		// @formatter:off
		return SslContextBuilder.forClient()
				.keyManager(keyManagerFactory)
				.trustManager(trustManagerFactory)
				.build();
		// @formatter:on
	}

	private static ClientHttpConnector createClientConnector(SslContext sslContext) {
		SslProvider sslProvider = SslProvider.builder().sslContext(sslContext).build();
		HttpClient httpClient = HttpClient.create().secure(sslProvider);
		return new ReactorClientHttpConnector(httpClient);
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplateBuilder builder,
			Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestTemplate restTemplate = builder
				.requestFactory(clientHttpRequestFactory)
				.messageConverters(Arrays.asList(
						new FormHttpMessageConverter(),
						new OAuth2AccessTokenResponseHttpMessageConverter()))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();

		// @formatter:off
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken(refreshToken ->
								refreshToken.accessTokenResponseClient(
										createRefreshTokenTokenResponseClient((restTemplate))))
						.clientCredentials(clientCredentials ->
								clientCredentials.accessTokenResponseClient(
										createClientCredentialsTokenResponseClient(restTemplate)))
						.provider(new DeviceCodeOAuth2AuthorizedClientProvider())
						.build();
		// @formatter:on

		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		// Set a contextAttributesMapper to obtain device_code from the request
		authorizedClientManager.setContextAttributesMapper(DeviceCodeOAuth2AuthorizedClientProvider
				.deviceCodeContextAttributesMapper());

		return authorizedClientManager;
	}

	private static OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> createRefreshTokenTokenResponseClient(RestTemplate restTemplate) {
		DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient =
				new DefaultRefreshTokenTokenResponseClient();
		refreshTokenTokenResponseClient.setRestOperations(restTemplate);

		OAuth2RefreshTokenGrantRequestEntityConverter refreshTokenGrantRequestEntityConverter =
				new OAuth2RefreshTokenGrantRequestEntityConverter();
		refreshTokenGrantRequestEntityConverter.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});
		refreshTokenTokenResponseClient.setRequestEntityConverter(refreshTokenGrantRequestEntityConverter);

		return refreshTokenTokenResponseClient;
	}

	private static OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> createClientCredentialsTokenResponseClient(RestTemplate restTemplate) {
		DefaultClientCredentialsTokenResponseClient clientCredentialsTokenResponseClient =
				new DefaultClientCredentialsTokenResponseClient();
		clientCredentialsTokenResponseClient.setRestOperations(restTemplate);

		OAuth2ClientCredentialsGrantRequestEntityConverter clientCredentialsGrantRequestEntityConverter =
				new OAuth2ClientCredentialsGrantRequestEntityConverter();
		clientCredentialsGrantRequestEntityConverter.addParametersConverter(authorizationGrantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add(OAuth2ParameterNames.CLIENT_ID, authorizationGrantRequest.getClientRegistration().getClientId());
			return parameters;
		});
		clientCredentialsTokenResponseClient.setRequestEntityConverter(clientCredentialsGrantRequestEntityConverter);

		return clientCredentialsTokenResponseClient;
	}

}
