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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.http.client.HttpClient;

import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.util.ResourceUtils;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Joe Grandja
 */
class WebClientUtils {

	static WebClient.Builder createSpringClient() throws Exception {
		return createWebClient("classpath:spring-client.p12", "secret", "spring-client", "secret");
	}

	static WebClient.Builder createTokenReplayClient() throws Exception {
		return createWebClient("classpath:token-replay-client.p12", "secret", "token-replay-client", "secret");
	}

	private static WebClient.Builder createWebClient(String keyStorePath, String keyStorePassword, String keyAlias, String keyPassword) throws Exception {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(new FileInputStream(ResourceUtils.getFile(keyStorePath)), keyStorePassword.toCharArray());

		List<Certificate> trustedCertificateList = new ArrayList<>();
		for (String alias : Collections.list(keyStore.aliases())) {
			if (keyStore.isCertificateEntry(alias)) {
				trustedCertificateList.add(keyStore.getCertificate(alias));
			}

		}
		X509Certificate[] trustedCertificates = trustedCertificateList.toArray(
				new X509Certificate[trustedCertificateList.size()]);

		PrivateKey clientPrivateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
		Certificate[] clientCertificateChain = keyStore.getCertificateChain(keyAlias);
		X509Certificate[] x509ClientCertificateChain = Arrays.asList(clientCertificateChain).toArray(
				new X509Certificate[clientCertificateChain.length]);

		SslContext sslContext = SslContextBuilder.forClient()
				.keyManager(clientPrivateKey, keyPassword, x509ClientCertificateChain)
				// FIXME
				// Add subject alternative name for resource server host to resource server certificate
				.trustManager(InsecureTrustManagerFactory.INSTANCE)
//				.trustManager(trustedCertificates)
				.build();

		HttpClient httpClient = HttpClient.create()
				.secure(sslContextSpec -> sslContextSpec.sslContext(sslContext));

		return WebClient.builder().clientConnector(new ReactorClientHttpConnector(httpClient));
	}

}
