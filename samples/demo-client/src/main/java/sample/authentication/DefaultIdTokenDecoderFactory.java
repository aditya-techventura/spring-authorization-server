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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;

/**
 * @author Joe Grandja
 */
public final class DefaultIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
	private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";
	private static final ClaimTypeConverter DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(
			OidcIdTokenDecoderFactory.createDefaultClaimTypeConverters());
	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();
	private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory =
			(clientRegistration) -> DEFAULT_CLAIM_TYPE_CONVERTER;
	private RestOperations restOperations;

	public void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.restOperations = restOperations;
	}

	@Override
	public JwtDecoder createDecoder(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		return this.jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), (key) -> {
			NimbusJwtDecoder jwtDecoder = buildDecoder(clientRegistration);
			jwtDecoder.setJwtValidator(createDefaultJwtValidator(clientRegistration));
			Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter = this.claimTypeConverterFactory
					.apply(clientRegistration);
			if (claimTypeConverter != null) {
				jwtDecoder.setClaimSetConverter(claimTypeConverter);
			}
			return jwtDecoder;
		});
	}

	private NimbusJwtDecoder buildDecoder(ClientRegistration clientRegistration) {
		String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
		if (!StringUtils.hasText(jwkSetUri)) {
			OAuth2Error oauth2Error = new OAuth2Error(MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
					"Failed to find a Signature Verifier for Client Registration: '"
							+ clientRegistration.getRegistrationId()
							+ "'. Check to ensure you have configured the JwkSet URI.",
					null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).restOperations(this.restOperations).build();
	}

	private static OAuth2TokenValidator<Jwt> createDefaultJwtValidator(ClientRegistration clientRegistration) {
		return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(),
				new OidcIdTokenValidator(clientRegistration));
	}

}
