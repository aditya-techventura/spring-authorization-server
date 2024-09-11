package org.example.secure.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.SslProvider;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.util.Iterator;
import java.util.function.Consumer;
import java.util.function.Supplier;

@Configuration
public class WebClientConfig {

	@Bean("default-client-web-client")
	public WebClient defaultClientWebClient(
			OAuth2AuthorizedClientManager authorizedClientManager,
			SslBundles sslBundles) throws Exception {

		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		// @formatter:off
		return WebClient.builder()
				.clientConnector(createClientConnector(sslBundles.getBundle("demo-client")))
				.apply(oauth2Client.oauth2Configuration())
				.build();
		// @formatter:on
	}

	private static ClientHttpConnector createClientConnector(SslBundle sslBundle) throws Exception {
		KeyManagerFactory keyManagerFactory = sslBundle.getManagers().getKeyManagerFactory();
		TrustManagerFactory trustManagerFactory = sslBundle.getManagers().getTrustManagerFactory();

		// @formatter:off
		SslContext sslContext = SslContextBuilder.forClient()
				.keyManager(keyManagerFactory)
				.trustManager(trustManagerFactory)
				.build();
		// @formatter:on

		SslProvider sslProvider = SslProvider.builder().sslContext(sslContext).build();
		// TODO: This uses Netty HTTPClient
		HttpClient httpClient = HttpClient.create().secure(sslProvider);
		return new ReactorClientHttpConnector(httpClient);
	}


	@Bean("default-client-http-request-factory")
	Supplier<ClientHttpRequestFactory> defaultClientHttpRequestFactory(SslBundles sslBundles) {
		return () -> {
			SslBundle sslBundle = sslBundles.getBundle("demo-client");
			final SSLContext sslContext = sslBundle.createSslContext();
			final SSLConnectionSocketFactory sslConnectionSocketFactory =
					new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
			final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", sslConnectionSocketFactory)
					.build();
			final BasicHttpClientConnectionManager connectionManager =
					new BasicHttpClientConnectionManager(socketFactoryRegistry);
			final CloseableHttpClient httpClient = HttpClients.custom()
					.setConnectionManager(connectionManager)
					.build();
			return new HttpComponentsClientHttpRequestFactory(httpClient);
		};
	}

	@Bean("self-signed-demo-client-http-request-factory")
	Supplier<ClientHttpRequestFactory> selfSignedDemoClientHttpRequestFactory(SslBundles sslBundles) {
		return () -> {
			SslBundle sslBundle = sslBundles.getBundle("self-signed-demo-client");
			final SSLContext sslContext = sslBundle.createSslContext();
			final SSLConnectionSocketFactory sslConnectionSocketFactory =
					new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
			final Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("https", sslConnectionSocketFactory)
					.build();
			final BasicHttpClientConnectionManager connectionManager =
					new BasicHttpClientConnectionManager(socketFactoryRegistry);
			final CloseableHttpClient httpClient = HttpClients.custom()
					.setConnectionManager(connectionManager)
					.build();
			return new HttpComponentsClientHttpRequestFactory(httpClient);
		};
	}
}
