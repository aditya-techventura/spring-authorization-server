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
package sample.config;

import java.io.File;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.ResourceUtils;

/**
 * @author Joe Grandja
 */
class RestTemplateUtils {
	private static final String KEYSTORE_PATH = "classpath:spring-client.p12";
	private static final String KEYSTORE_PASSWORD = "secret";
	private static final String KEYSTORE_TYPE = "pkcs12";

	static Supplier<ClientHttpRequestFactory> createClientHttpRequestFactory() throws Exception {
		final File keyStorePath = ResourceUtils.getFile(KEYSTORE_PATH);
		final SSLContext sslContext = SSLContextBuilder.create()
				.setKeyStoreType(KEYSTORE_TYPE)
				.loadKeyMaterial(
						keyStorePath,
						KEYSTORE_PASSWORD.toCharArray(),
						KEYSTORE_PASSWORD.toCharArray())
				.loadTrustMaterial(
						keyStorePath,
						KEYSTORE_PASSWORD.toCharArray())
				.build();
		return () -> {
			HttpClient client = HttpClients.custom()
					.setSSLContext(sslContext)
					.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
					.build();
			return new HttpComponentsClientHttpRequestFactory(client);
		};
	}

}
