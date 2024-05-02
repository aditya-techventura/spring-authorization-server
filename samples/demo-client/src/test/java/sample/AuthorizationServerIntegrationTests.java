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
package sample;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests against a Spring Authorization Server using spring-boot-testjars.
 *
 * @see <a target="_blank" href="https://github.com/spring-projects-experimental/spring-boot-testjars">spring-boot-testjars</a>
 */
@SpringBootTest(classes = AuthorizationServerContainerConfig.class)
public class AuthorizationServerIntegrationTests {

	@Value("${spring.security.oauth2.client.provider.spring.issuer-uri}")
	private String issuerUri;

	// @formatter:off
	private final RestClient restClient  = RestClient.builder()
			.messageConverters(converters ->
					converters.add(0, new OAuth2AccessTokenResponseHttpMessageConverter()))
			.build();
	// @formatter:on

	@Test
	public void requestWhenTokenRequestClientCredentialsGrantThenTokenResponse() {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		params.add(OAuth2ParameterNames.SCOPE, "scope-1");

		// @formatter:off
		ResponseEntity<OAuth2AccessTokenResponse> tokenResponse = this.restClient.post()
				.uri(this.issuerUri + "/oauth2/token")
				.body(params)
				.headers((headers) -> headers.setBasicAuth("client-1", "secret"))
				.retrieve()
				.toEntity(OAuth2AccessTokenResponse.class);
		// @formatter:on

		assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(tokenResponse.getBody().getAccessToken()).isNotNull();
	}

}
