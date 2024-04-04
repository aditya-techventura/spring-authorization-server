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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.io.Serializable;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Token Exchange Grant
 * to represent an actor in a composite token (e.g. the "delegation" use case).
 *
 * @author Steve Riesenberg
 * @since 1.3
 * @see OAuth2CompositeAuthenticationToken
 */

/*
Spec references:

The act claim value is a JSON object, and members in the JSON object are claims that identify the actor.
The claims that make up the act claim identify and possibly provide additional information about the actor.
For example, the combination of the two claims iss and sub might be necessary to uniquely identify an actor.

// TODO I'm not sure this needs to be an Authentication - consider a simple domain class, for example:

	public class OAuth2TokenExchangeActor {
		private Map<String, Object> claims;		// May include iss, sub, etc.
		private @Nullable OAuth2TokenExchangeActor previousActor;

	}

 */

public class OAuth2ActorAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
	// TODO Remove implements Serializable (Authentication extends Serializable)

	private final String name;

	public OAuth2ActorAuthenticationToken(String name) {
		super(Collections.emptyList());
		Assert.hasText(name, "name cannot be empty");
		this.name = name;
	}

	@Override
	public Object getPrincipal() {
		return this.name;
	}

	@Override
	public Object getCredentials() {
		return null;
	}
}
