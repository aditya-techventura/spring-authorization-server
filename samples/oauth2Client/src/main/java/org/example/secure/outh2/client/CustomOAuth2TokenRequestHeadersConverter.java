package org.example.secure.outh2.client;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;

import java.util.List;

public class CustomOAuth2TokenRequestHeadersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, HttpHeaders> {

	@Override
	public HttpHeaders convert(T source) {
		HttpHeaders headers = new HttpHeaders();
		// TODO: Add Brand, App, Correlation ID, RequestId etc headers here
		// This is for example
		headers.add("X-Brand", "NWG");
		headers.add("X-App-Name", "Mobile");
		headers.add("X-CorrelationId","dwdfwer2342432");
		headers.add("X-RequestId", "cse4r23rsdfssf");
		return headers;
	}
}
