package org.example.secure.config;

import org.example.secure.filter.OAuth2ClientInterceptor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInitializer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.RestClient;

import java.util.function.Supplier;

@Configuration
public class RestClientConfig {

	@Lazy
	@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
	@Bean
	RestClient restClientJwt(RestClient.Builder builder,
			OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository,
			@Qualifier("default-client-http-request-factory") Supplier<ClientHttpRequestFactory> clientHttpRequestFactory) {

		ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("private-key-jwt-messaging-client-client-credentials");

		ClientHttpRequestInitializer initializer = new OAuth2ClientInterceptor(authorizedClientManager, clientRegistration);

		return builder.requestFactory(clientHttpRequestFactory.get()).requestInitializer(initializer).build();
	}

}
