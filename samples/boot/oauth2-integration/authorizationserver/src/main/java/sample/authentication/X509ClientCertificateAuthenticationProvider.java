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
package sample.authentication;

import java.security.cert.X509Certificate;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * @author Joe Grandja
 */
public final class X509ClientCertificateAuthenticationProvider implements AuthenticationProvider {
	private static final String X509_CERTIFICATE_SUBJECT_DN_SETTING_NAME = "settings.client.x509-certificate-subjectDN";
	private final RegisteredClientRepository registeredClientRepository;

	public X509ClientCertificateAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication =
				(OAuth2ClientAuthenticationToken) authentication;

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
		if (!x509Certificate.getSubjectDN().getName().equals(
				registeredClient.getClientSettings().getSetting(X509_CERTIFICATE_SUBJECT_DN_SETTING_NAME))) {
			throwInvalidClient();
		}

		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), clientAuthentication.getCredentials());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient() {
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

}
