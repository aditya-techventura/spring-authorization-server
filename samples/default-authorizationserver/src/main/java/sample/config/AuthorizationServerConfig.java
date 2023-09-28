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

import java.util.Set;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import sample.authentication.CustomCodeGrantAuthenticationProvider;
import sample.web.authentication.CustomCodeGrantAuthenticationConverter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(
			HttpSecurity http,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		// @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
			.tokenEndpoint(tokenEndpoint ->
				tokenEndpoint
					.accessTokenRequestConverter(
						new CustomCodeGrantAuthenticationConverter()
					)
					.authenticationProvider(
						new CustomCodeGrantAuthenticationProvider(
								authorizationService, tokenGenerator)
					)
			);

		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));
		// @formatter:on

		return http.build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		// @formatter:off
		return AuthorizationServerSettings.builder()
				.authorizationEndpoint("/oauth2/v1/authorize")
				.tokenEndpoint("/oauth2/v1/token")
				.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
				.tokenRevocationEndpoint("/oauth2/v1/revoke")
				.build();
		// @formatter:on
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		jwtGenerator.setJwtCustomizer(jwtTokenCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		accessTokenGenerator.setAccessTokenCustomizer(opaqueTokenCustomizer());
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> authorities = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
					claims.put("authorities", authorities);
				});
			}
		};
	}

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> opaqueTokenCustomizer() {
		return (context) -> {
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				context.getClaims().claims((claims) -> {
					Set<String> authorities = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
					claims.put("authorities", authorities);
				});
			}
		};
	}

}
