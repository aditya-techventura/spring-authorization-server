package org.example.secure.config;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.example.secure.filter.OAuth2ClientInterceptor;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInitializer;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestClient;

import javax.net.ssl.SSLContext;
import java.util.Map;

@Configuration
public class RestClientDynamicBeanRegistration implements BeanDefinitionRegistryPostProcessor {

	private ClientBackendMappingProperties clientBackendMappingProperties = new ClientBackendMappingProperties();

	private SslBundles sslBundles;

	private OAuth2AuthorizedClientManager authorizedClientManager;

	private ClientRegistrationRepository clientRegistrationRepository;

	public RestClientDynamicBeanRegistration(Environment environment) {
		Binder binder = Binder.get(environment);
		Map<String, ClientBackendMappingProperties.ClientConfig> properties = binder.bind("client-backend-mapping.config", Bindable.mapOf(String.class, ClientBackendMappingProperties.ClientConfig.class)).get();
		this.clientBackendMappingProperties.setConfig(properties);
	}

	@Autowired
	public RestClientDynamicBeanRegistration(ClientBackendMappingProperties clientBackendMappingProperties, SslBundles sslBundles, OAuth2AuthorizedClientManager authorizedClientManager, ClientRegistrationRepository clientRegistrationRepository) {
		this.clientBackendMappingProperties = clientBackendMappingProperties;
		this.sslBundles = sslBundles;
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {

		for (Map.Entry<String, ClientBackendMappingProperties.ClientConfig> entry : clientBackendMappingProperties.getConfig().entrySet()) {
			ClientBackendMappingProperties.ClientConfig clientConfig = entry.getValue();
			// TODO: Check if its null or not
			ClientHttpRequestFactory clientHttpRequestFactory = getClientHttpRequestFactory(clientConfig.getSslBundleName());
			ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientConfig.getClientName());
			ClientHttpRequestInitializer initializer = new OAuth2ClientInterceptor(authorizedClientManager, clientRegistration);

			BeanDefinition beanDefinition = BeanDefinitionBuilder
					.genericBeanDefinition(RestClient.class, () -> RestClient.builder()
							.requestFactory(clientHttpRequestFactory)
							.requestInitializer(initializer)
							.build())
					.getBeanDefinition();

			registry.registerBeanDefinition(entry.getKey(), beanDefinition);
		}
	}


	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		BeanDefinitionRegistryPostProcessor.super.postProcessBeanFactory(beanFactory);
		// No implementation required for now
	}

	private ClientHttpRequestFactory getClientHttpRequestFactory(String sslBundleName) {
		SslBundle sslBundle = sslBundles.getBundle(sslBundleName);
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
	}

	public ClientBackendMappingProperties getClientBackendMappingProperties() {
		return clientBackendMappingProperties;
	}

	public void setClientBackendMappingProperties(ClientBackendMappingProperties clientBackendMappingProperties) {
		this.clientBackendMappingProperties = clientBackendMappingProperties;
	}

	public SslBundles getSslBundles() {
		return sslBundles;
	}

	public void setSslBundles(SslBundles sslBundles) {
		this.sslBundles = sslBundles;
	}

	public OAuth2AuthorizedClientManager getAuthorizedClientManager() {
		return authorizedClientManager;
	}

	public void setAuthorizedClientManager(OAuth2AuthorizedClientManager authorizedClientManager) {
		this.authorizedClientManager = authorizedClientManager;
	}

	public ClientRegistrationRepository getClientRegistrationRepository() {
		return clientRegistrationRepository;
	}

	public void setClientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
	}
}

