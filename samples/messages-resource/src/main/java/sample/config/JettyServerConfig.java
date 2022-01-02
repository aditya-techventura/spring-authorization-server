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

import java.net.InetSocketAddress;
import java.util.Collections;

import javax.net.ssl.SSLContext;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class JettyServerConfig {

	@Value("${server.port}")
	private int serverPort;

	@Bean
	public WebServerFactoryCustomizer<JettyServletWebServerFactory> jettyServerFactoryCustomizer(SSLContext sslContext) {
		return (factory) -> {
			JettyServerCustomizer jettyServerCustomizer = server -> {
				SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
				sslContextFactory.setSslContext(sslContext);
				sslContextFactory.setProtocol("TLS");
				sslContextFactory.setNeedClientAuth(true);
				sslContextFactory.setWantClientAuth(true);
				sslContextFactory.setSniRequired(false);

				HttpConfiguration httpsConfig = new HttpConfiguration();
				SecureRequestCustomizer secureRequestCustomizer = new SecureRequestCustomizer();
				secureRequestCustomizer.setSniHostCheck(false);
				httpsConfig.addCustomizer(secureRequestCustomizer);

				ServerConnector sslConnector = new ServerConnector(
						server, sslContextFactory, new HttpConnectionFactory(httpsConfig));

				InetSocketAddress address = new InetSocketAddress(this.serverPort);
				sslConnector.setHost(address.getHostString());
				sslConnector.setPort(address.getPort());

				server.setConnectors(new Connector[] {sslConnector});
			};
			factory.setServerCustomizers(Collections.singletonList(jettyServerCustomizer));
		};
	}

}
