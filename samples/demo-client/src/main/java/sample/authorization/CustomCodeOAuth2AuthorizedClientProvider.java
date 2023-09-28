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
package sample.authorization;

import java.time.Clock;
import java.time.Duration;

import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;

public final class CustomCodeOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {
	private OAuth2AccessTokenResponseClient<CustomCodeGrantRequest> accessTokenResponseClient =
			new CustomCodeAccessTokenResponseClient();
	private Duration clockSkew = Duration.ofSeconds(60);
	private Clock clock = Clock.systemUTC();

	public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<CustomCodeGrantRequest> accessTokenResponseClient) {
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public void setClock(Clock clock) {
		this.clock = clock;
	}

	@Override
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		ClientRegistration clientRegistration = context.getClientRegistration();
		if (!"urn:ietf:params:oauth:grant-type:custom_code".equals(clientRegistration.getAuthorizationGrantType().getValue())) {
			return null;
		}
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
			// If client is already authorized but access token is NOT expired than no
			// need for re-authorization
			return null;
		}
		if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
			// If client is already authorized but access token is expired and a
			// refresh token is available, delegate to refresh_token.
			return null;
		}
		CustomCodeGrantRequest customCodeGrantRequest =
				new CustomCodeGrantRequest(clientRegistration, "code1234");		// TODO Obtain code from context
		OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, customCodeGrantRequest);
		return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
				tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
	}

	private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
			CustomCodeGrantRequest customCodeGrantRequest) {
		try {
			return this.accessTokenResponseClient.getTokenResponse(customCodeGrantRequest);
		} catch (OAuth2AuthorizationException ex) {
			throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
		}
	}

	private boolean hasTokenExpired(OAuth2Token token) {
		return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
	}

}
