package org.example.secure.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

public class OAuth2RestClientHelper {

	@Autowired
	SslBundles sslBundles;

	public RestClient getRestClientBasedOnConfig(String clientRegistrationId) {

		return RestClient.builder().build();
	}

}
