/*
 * Copyright 2020-2022 the original author or authors.
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
package sample.authentication;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author Joe Grandja
 */
public final class X509ClientCertificateAuthenticationProvider implements AuthenticationProvider {
	private static final String SPIFFE_ID_SETTING_NAME = "settings.client.spiffeId";
	private static final ClientAuthenticationMethod TLS_CLIENT_AUTH_AUTHENTICATION_METHOD =
			new ClientAuthenticationMethod("tls_client_auth");
	private final RegisteredClientRepository registeredClientRepository;

	public X509ClientCertificateAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

		if (!TLS_CLIENT_AUTH_AUTHENTICATION_METHOD.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}

		String clientId = clientAuthentication.getPrincipal().toString();
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwInvalidClient();
		}

		if (!registeredClient.getClientAuthenticationMethods().contains(
				clientAuthentication.getClientAuthenticationMethod())) {
			throwInvalidClient();
		}

		if (!(clientAuthentication.getCredentials() instanceof X509Certificate)) {
			throwInvalidClient();
		}

		X509Certificate x509Certificate = (X509Certificate) clientAuthentication.getCredentials();
		if (!hasSubjectAlternativeName(registeredClient.getClientSettings().getSetting(SPIFFE_ID_SETTING_NAME), x509Certificate)) {
			throwInvalidClient();
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), x509Certificate);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static boolean hasSubjectAlternativeName(String subjectAlternativeName, X509Certificate x509Certificate) {
		if (!StringUtils.hasText(subjectAlternativeName)) {
			return false;
		}

		Collection<List<?>> subjectAlternativeNames = null;
		try {
			subjectAlternativeNames = x509Certificate.getSubjectAlternativeNames();
		} catch (CertificateParsingException ex) { }

		if (CollectionUtils.isEmpty(subjectAlternativeNames)) {
			return false;
		}

		for (List<?> sanList : subjectAlternativeNames) {
			for (Object san : sanList) {
				if (san instanceof String &&
						san.equals(subjectAlternativeName)) {
					return true;
				}
			}
		}

		return false;
	}

	private static void throwInvalidClient() {
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

}
