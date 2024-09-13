package org.example.secure.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@ConfigurationProperties(prefix = "client-backend-mapping")
public class ClientBackendMappingProperties {

	private Map<String, ClientConfig> config;

	public Map<String, ClientConfig> getConfig() {
		return config;
	}

	public void setConfig(Map<String, ClientConfig> config) {
		this.config = config;
	}

	@AllArgsConstructor
	public static class ClientConfig {
		private String clientKey;
		private String clientName;
		private String baseUri;
		private String sslBundleName;

		public String getClientKey() {
			return clientKey;
		}

		public void setClientKey(String clientKey) {
			this.clientKey = clientKey;
		}

		public String getClientName() {
			return clientName;
		}

		public void setClientName(String clientName) {
			this.clientName = clientName;
		}

		public String getBaseUri() {
			return baseUri;
		}

		public void setBaseUri(String baseUri) {
			this.baseUri = baseUri;
		}

		public String getSslBundleName() {
			return sslBundleName;
		}

		public void setSslBundleName(String sslBundleName) {
			this.sslBundleName = sslBundleName;
		}
	}
}
