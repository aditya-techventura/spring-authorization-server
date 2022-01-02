/*
 * Copyright 2020-2023 the original author or authors.
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

import sample.authentication.DefaultIdTokenDecoderFactory;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;

/**
 * @author Joe Grandja
 * @author Dmitriy Dubson
 * @author Steve Riesenberg
 * @since 0.0.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

	@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers("/webjars/**", "/assets/**");
	}

	// @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(
			HttpSecurity http,
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient,
			OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) throws Exception {

		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/logged-out").permitAll()
					.anyRequest().authenticated()
			)
			.oauth2Login(oauth2Login ->
				oauth2Login
					.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint
							.accessTokenResponseClient(authorizationCodeTokenResponseClient)
					)
					.userInfoEndpoint(userInfoEndpoint ->
						userInfoEndpoint
							.oidcUserService(oidcUserService)
					)
					.loginPage("/oauth2/authorization/messaging-client-oidc")
				)
				.oauth2Client(oauth2Client ->
					oauth2Client
						.authorizationCodeGrant(authorizationCodeGrant ->
							authorizationCodeGrant
								.accessTokenResponseClient(authorizationCodeTokenResponseClient))
				)
			.logout(logout ->
				logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
		return http.build();
	}
	// @formatter:on

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient(
			RestTemplateBuilder builder,
			Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestTemplate restTemplate = builder
				.requestFactory(clientHttpRequestFactory)
				.messageConverters(Arrays.asList(
						new FormHttpMessageConverter(),
						new OAuth2AccessTokenResponseHttpMessageConverter()))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();

		DefaultAuthorizationCodeTokenResponseClient authorizationCodeTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		authorizationCodeTokenResponseClient.setRestOperations(restTemplate);
		authorizationCodeTokenResponseClient.setRequestEntityConverter(new OAuth2AuthorizationCodeGrantRequestEntityConverter());

		return authorizationCodeTokenResponseClient;
	}
	@Bean
	OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(
			RestTemplateBuilder builder,
			Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestTemplate restTemplate = builder
				.requestFactory(clientHttpRequestFactory)
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();

		DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
		defaultOAuth2UserService.setRestOperations(restTemplate);

		OidcUserService oidcUserService = new OidcUserService();
		oidcUserService.setOauth2UserService(defaultOAuth2UserService);

		return oidcUserService;
	}

	@Bean
	JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(RestTemplateBuilder builder,
			Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		RestTemplate restTemplate = builder
				.requestFactory(clientHttpRequestFactory)
				.build();

		DefaultIdTokenDecoderFactory defaultIdTokenDecoderFactory = new DefaultIdTokenDecoderFactory();
		defaultIdTokenDecoderFactory.setRestOperations(restTemplate);

		return defaultIdTokenDecoderFactory;
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

		// Set the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logged-out");

		return oidcLogoutSuccessHandler;
	}

}
