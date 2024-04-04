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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Token Exchange Grant
 * to represent the principal in a composite token (e.g. the "delegation" use case).
 *
 * @author Steve Riesenberg
 * @since 1.3
 * @see OAuth2TokenExchangeAuthenticationToken
 */
// TODO Rename to OAuth2TokenExchangeCompositeAuthenticationToken
// TODO See comments in OAuth2ActorAuthenticationToken re: OAuth2TokenExchangeActor
public class OAuth2CompositeAuthenticationToken extends AbstractAuthenticationToken implements Serializable {
	// TODO Remove implements Serializable (Authentication extends Serializable)

	private final Authentication subject;		// subjectAuthorizationPrincipal

	private final List<Authentication> actors;

//	private final List<OAuth2TokenExchangeActor> actors;

/*

	public class OAuth2TokenExchangeActor {
		private Map<String, Object> claims;		// May include iss, sub, etc.

	}


 */

	public OAuth2CompositeAuthenticationToken(Authentication subject, List<Authentication> actors) {
		super(subject != null ? subject.getAuthorities() : null);
		Assert.notNull(subject, "subject cannot be null");
		Assert.notNull(actors, "actors cannot be null");
		this.subject = subject;
		this.actors = Collections.unmodifiableList(new ArrayList<>(actors));
		setDetails(subject.getDetails());
		setAuthenticated(subject.isAuthenticated());
	}

	@Override
	public Object getPrincipal() {
		return this.subject.getPrincipal();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	public Authentication getSubject() {
		return this.subject;
	}

	public List<Authentication> getActors() {
		return this.actors;
	}

}
