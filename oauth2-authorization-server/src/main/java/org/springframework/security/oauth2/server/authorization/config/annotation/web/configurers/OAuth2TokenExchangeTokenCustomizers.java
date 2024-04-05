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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2CompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.CollectionUtils;

/**
 * @author Steve Riesenberg
 * @since 1.3
 */
// TODO Add tests?
final class OAuth2TokenExchangeTokenCustomizers {

	private OAuth2TokenExchangeTokenCustomizers() {
	}

	static OAuth2TokenCustomizer<JwtEncodingContext> jwt() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessToken() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	// TODO
	// I think we should move this logic into JwtGenerator.generate() and OAuth2AccessTokenGenerator.generate().
	// Similar logic can be found in JwtGenerator for AuthorizationGrantType.AUTHORIZATION_CODE and AuthorizationGrantType.REFRESH_TOKEN
	// We could share this logic as a utility method between the 2 token generator's
	private static void customize(OAuth2TokenContext context, Map<String, Object> claims) {
		if (!AuthorizationGrantType.TOKEN_EXCHANGE.equals(context.getAuthorizationGrantType())) {
			return;
		}

		if (context.getAuthorizationGrant() instanceof OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication) {
			// Customize the token claims when audience is present in the request
			List<String> audience = tokenExchangeAuthentication.getAudiences();
			if (!CollectionUtils.isEmpty(audience)) {
				// FIXME I think this will override the default `aud` `registeredClient.getClientId()`? We should append to it
				claims.put(OAuth2TokenClaimNames.AUD, audience);

				// Spec reference:
				/*
					An authorization server may be unwilling or unable to fulfill any token request,
					but the likelihood of an unfulfillable request is significantly higher when very broad access rights are being solicited.
					As such, in the absence of specific knowledge about the relationship of systems in a deployment,
					clients should exercise discretion in the breadth of the access requested, particularly the number of target services.
					An authorization server can use the invalid_target error code, defined in Section 2.2.2,
					to inform a client that it requested access to too many target services simultaneously.

				// TODO As per above, I wonder if we should check the number of aud requested? And potentially limit the number?

				 */

			}
		}

		// As per https://datatracker.ietf.org/doc/html/rfc8693#section-4.1,
		// we handle a composite principal with an actor by adding an "act"
		// claim with a "sub" claim of the actor.
		//
		// If more than one actor is present, we create a chain of delegation by
		// nesting "act" claims.
		if (context.getPrincipal() instanceof OAuth2CompositeAuthenticationToken compositeAuthenticationToken) {
			Map<String, Object> currentClaims = claims;
			for (Authentication actorPrincipal : compositeAuthenticationToken.getActors()) {
				Map<String, Object> actClaim = new HashMap<>();
				actClaim.put("sub", actorPrincipal.getName());
				currentClaims.put("act", Collections.unmodifiableMap(actClaim));
				currentClaims = actClaim;
			}
		}
	}

}
