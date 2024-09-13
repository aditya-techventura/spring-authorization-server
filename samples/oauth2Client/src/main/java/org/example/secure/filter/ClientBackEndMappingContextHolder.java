package org.example.secure.filter;

import org.springframework.util.Assert;

public class ClientBackEndMappingContextHolder {

	private static final ThreadLocal<String> MAPPING_CONTEXT = new ThreadLocal<>();

	private ClientBackEndMappingContextHolder() {
	}

	public static void set(String clientMappingContext) {
		Assert.notNull(clientMappingContext, "The Client to Backend Mapping Context is missing");
		MAPPING_CONTEXT.set(clientMappingContext);
	}

	public static String getClientBackendMappingContext() {
		return MAPPING_CONTEXT.get();
	}

	public static void clear() {
		MAPPING_CONTEXT.remove();
	}
}
