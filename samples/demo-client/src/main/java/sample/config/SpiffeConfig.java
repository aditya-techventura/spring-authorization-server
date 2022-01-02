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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.spiffe.provider.SpiffeKeyManager;
import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.provider.SpiffeTrustManager;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.svid.x509svid.X509Svid;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class SpiffeConfig {
	private static final String DEFAULT_SPIFFE_SOCKET_PATH = "unix:/tmp/spire-agent/public/api.sock";

	@Value("${spiffe.workload.id}")
	private String spiffeWorkloadId;

	@Value("${spiffe.workload.accepted-ids}")
	private String[] acceptedSpiffeWorkloadIds;

	@Bean
	X509Source x509Source() throws Exception {
		SpiffeId spiffeId = SpiffeId.parse(this.spiffeWorkloadId);

		// @formatter:off
		DefaultX509Source.X509SourceOptions x509SourceOptions =
				DefaultX509Source.X509SourceOptions
						.builder()
						.spiffeSocketPath(DEFAULT_SPIFFE_SOCKET_PATH)
						.svidPicker(svids -> {
							for (X509Svid svid: svids) {
								if (svid.getSpiffeId().equals(spiffeId)) {
									return svid;
								}
							}
							return null;
						})
						.build();
		// @formatter:on

		return DefaultX509Source.newSource(x509SourceOptions);
	}

	@Bean
	SSLContext clientSslContext(X509Source x509Source) throws Exception {
		Set<SpiffeId> acceptedSpiffeIds = new HashSet<>();
		Arrays.asList(this.acceptedSpiffeWorkloadIds).forEach(id -> acceptedSpiffeIds.add(SpiffeId.parse(id)));

		// @formatter:off
		SpiffeSslContextFactory.SslContextOptions sslContextOptions =
				SpiffeSslContextFactory.SslContextOptions
						.builder()
						.acceptedSpiffeIdsSupplier(() -> acceptedSpiffeIds)
						.x509Source(x509Source)
						.build();
		// @formatter:on

		return SpiffeSslContextFactory.getSslContext(sslContextOptions);
	}

	@Bean
	SslContext nettyClientSslContext(X509Source x509Source) throws Exception {
		Set<SpiffeId> acceptedSpiffeIds = new HashSet<>();
		Arrays.asList(this.acceptedSpiffeWorkloadIds).forEach(id -> acceptedSpiffeIds.add(SpiffeId.parse(id)));

		SpiffeKeyManager keyManager = new SpiffeKeyManager(x509Source);
		SpiffeTrustManager trustManager = new SpiffeTrustManager(x509Source, () -> acceptedSpiffeIds);

		// @formatter:off
		return SslContextBuilder.forClient()
				.keyManager(keyManager)
				.trustManager(trustManager)
				.build();
		// @formatter:on
	}

}
