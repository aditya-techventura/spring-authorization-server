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

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * @author Joe Grandja
 */
public final class X509ClientCertificateClaimValidator implements OAuth2TokenValidator<Jwt> {
	private static final OAuth2Error INVALID_CLIENT_ERROR = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		X509Certificate x509Certificate = extractClientCertificate(RequestContextHolder.getRequestAttributes());
		if (x509Certificate == null) {
			return OAuth2TokenValidatorResult.failure(INVALID_CLIENT_ERROR);
		}

		String sha256Thumbprint = computeThumbprint(x509Certificate);
		if (sha256Thumbprint == null ||
				!sha256Thumbprint.equals(jwt.getClaim("x5client#S256"))) {
			return OAuth2TokenValidatorResult.failure(INVALID_CLIENT_ERROR);
		}

		return OAuth2TokenValidatorResult.success();
	}

	private static X509Certificate extractClientCertificate(RequestAttributes requestAttributes) {
		X509Certificate[] certs = (X509Certificate[]) requestAttributes.getAttribute(
				"javax.servlet.request.X509Certificate", RequestAttributes.SCOPE_REQUEST);
		if (certs != null && certs.length > 0) {
			return certs[0];
		}
		return null;
	}

	private static String computeThumbprint(X509Certificate x509Certificate) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] digest = md.digest(x509Certificate.getEncoded());
			return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception ex) {
			return null;
		}
	}

}
