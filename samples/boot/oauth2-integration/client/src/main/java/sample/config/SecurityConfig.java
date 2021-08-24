/*
 * Copyright 2020-2021 the original author or authors.
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

import sample.authentication.OidcIdTokenDecoderFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient;

	@Bean
	WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/webjars/**");
	}

	// @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.oauth2Login(oauth2Login ->
				oauth2Login
					.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint
							.accessTokenResponseClient(this.authorizationCodeTokenResponseClient))
					.loginPage("/oauth2/authorization/messaging-client-oidc"))
			.oauth2Client(oauth2Client ->
				oauth2Client
					.authorizationCodeGrant(authorizationCodeGrant ->
						authorizationCodeGrant
							.accessTokenResponseClient(this.authorizationCodeTokenResponseClient)));

		return http.build();
	}
	// @formatter:on

	@Bean
	OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> authorizationCodeTokenResponseClient(
			RestTemplateBuilder builder) throws Exception {

		RestTemplate restTemplate = builder
				.requestFactory(RestTemplateUtils.createClientHttpRequestFactory())
				.messageConverters(Arrays.asList(
						new FormHttpMessageConverter(),
						new OAuth2AccessTokenResponseHttpMessageConverter()))
				.errorHandler(new OAuth2ErrorResponseErrorHandler())
				.build();

		DefaultAuthorizationCodeTokenResponseClient authorizationCodeTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		authorizationCodeTokenResponseClient.setRestOperations(restTemplate);

		return authorizationCodeTokenResponseClient;
	}

	@Bean
	JwtDecoderFactory<ClientRegistration> jwtDecoderFactory(RestTemplateBuilder builder) throws Exception {
		RestTemplate restTemplate = builder
				.requestFactory(RestTemplateUtils.createClientHttpRequestFactory())
				.build();

		OidcIdTokenDecoderFactory oidcIdTokenDecoderFactory = new OidcIdTokenDecoderFactory();
		oidcIdTokenDecoderFactory.setRestOperations(restTemplate);

		return oidcIdTokenDecoderFactory;
	}

}
