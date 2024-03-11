/*
 * Copyright 2020-2024 the original author or authors.
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
package sample;

import java.io.FileOutputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author Joe Grandja
 * @since 1.3
 */
@SpringBootApplication
public class PkiGeneratorApplication implements CommandLineRunner {
	private static final String BC_PROVIDER = "BC";

	public static void main(String[] args) {
		SpringApplication.run(PkiGeneratorApplication.class, args);
	}
	@Override
	public void run(String... args) throws Exception {
		String baseDistinguishedName = "OU=Spring Samples, O=Spring, C=US";

		// Generate the Root certificate (Trust Anchor or most-trusted CA) and keystore file
		String commonName = "spring-samples-trusted-ca";
		String rootCommonName = commonName;
		String distinguishedName = "CN=" + commonName + ", " + baseDistinguishedName;
		KeyPair rootKeyPair = BouncyCastleUtils.generateRSAKeyPair();
		X509Certificate rootCertificate = BouncyCastleUtils.createTrustAnchorCertificate(rootKeyPair, distinguishedName);
		writeCertificatePEMEncoded(rootCertificate, "./samples/pki-generator/pki/" + commonName + ".pem");
		createKeystoreFile(rootKeyPair, new Certificate[] {rootCertificate}, commonName,
				null, "./samples/pki-generator/pki/" + commonName + "-keystore.p12");
		TrustedCertificateHolder[] rootTrustedCertificate = { new TrustedCertificateHolder(rootCertificate, rootCommonName) };

		// Generate the CA (intermediary) certificate and keystore file
		commonName = "spring-samples-ca";
		String caCommonName = commonName;
		distinguishedName = "CN=" + commonName + ", " + baseDistinguishedName;
		KeyPair caKeyPair = BouncyCastleUtils.generateRSAKeyPair();
		X509Certificate caCertificate = BouncyCastleUtils.createCACertificate(
				rootCertificate, rootKeyPair.getPrivate(), caKeyPair.getPublic(), distinguishedName);
		writeCertificatePEMEncoded(caCertificate, "./samples/pki-generator/pki/" + commonName + ".pem");
		createKeystoreFile(caKeyPair, new Certificate[] {caCertificate, rootCertificate}, commonName,
				rootTrustedCertificate, "./samples/pki-generator/pki/" + commonName + "-keystore.p12");
		TrustedCertificateHolder[] caTrustedCertificate = { new TrustedCertificateHolder(caCertificate, caCommonName) };

		// Generate the certificate and keystore file for the demo-client sample
		commonName = "demo-client-sample";
		distinguishedName = "CN=" + commonName + ", " + baseDistinguishedName;
		KeyPair demoClientKeyPair = BouncyCastleUtils.generateRSAKeyPair();
		X509Certificate demoClientCertificate = BouncyCastleUtils.createEndEntityCertificate(
				caCertificate, caKeyPair.getPrivate(), demoClientKeyPair.getPublic(), distinguishedName);
		demoClientCertificate.verify(caCertificate.getPublicKey(), BC_PROVIDER);
		createKeystoreFile(demoClientKeyPair, new Certificate[] {demoClientCertificate, caCertificate, rootCertificate}, commonName,
				caTrustedCertificate, "./samples/demo-client/src/main/resources/keystore.p12");

		// Generate the certificate and keystore file for the messages-resource sample
		commonName = "messages-resource-sample";
		distinguishedName = "CN=" + commonName + ", " + baseDistinguishedName;
		KeyPair messagesResourceKeyPair = BouncyCastleUtils.generateRSAKeyPair();
		X509Certificate messagesResourceCertificate = BouncyCastleUtils.createEndEntityCertificate(
				caCertificate, caKeyPair.getPrivate(), messagesResourceKeyPair.getPublic(), distinguishedName);
		messagesResourceCertificate.verify(caCertificate.getPublicKey(), BC_PROVIDER);
		createKeystoreFile(messagesResourceKeyPair, new Certificate[] {messagesResourceCertificate, caCertificate, rootCertificate}, commonName,
				caTrustedCertificate, "./samples/messages-resource/src/main/resources/keystore.p12");

		// Generate the certificate and keystore file for the demo-authorizationserver sample
		commonName = "demo-authorizationserver-sample";
		distinguishedName = "CN=" + commonName + ", " + baseDistinguishedName;
		KeyPair demoAuthorizationServerKeyPair = BouncyCastleUtils.generateRSAKeyPair();
		X509Certificate demoAuthorizationServerCertificate = BouncyCastleUtils.createEndEntityCertificate(
				caCertificate, caKeyPair.getPrivate(), demoAuthorizationServerKeyPair.getPublic(), distinguishedName);
		demoAuthorizationServerCertificate.verify(caCertificate.getPublicKey(), BC_PROVIDER);
		createKeystoreFile(demoAuthorizationServerKeyPair, new Certificate[] {demoAuthorizationServerCertificate, caCertificate, rootCertificate}, commonName,
				caTrustedCertificate, "./samples/demo-authorizationserver/src/main/resources/keystore.p12");
	}

	private static void createKeystoreFile(KeyPair keyPair, Certificate[] certificateChain, String alias,
			TrustedCertificateHolder[] trustedCertificates, String fileName) throws Exception {

		KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
		keyStore.load(null, null);
		keyStore.setKeyEntry(alias, keyPair.getPrivate(), "password".toCharArray(), certificateChain);
		if (trustedCertificates != null && trustedCertificates.length > 0) {
			for (TrustedCertificateHolder trustedCertificate : trustedCertificates) {
				keyStore.setCertificateEntry(trustedCertificate.alias, trustedCertificate.certificate);
			}
		}
		Path path = Paths.get(fileName);
		Path parent = path.getParent();
		if (parent != null && Files.notExists(parent)) {
			Files.createDirectories(parent);
		}
		FileOutputStream fos = new FileOutputStream(fileName);
		keyStore.store(fos, "password".toCharArray());
	}

	private static void writeCertificatePEMEncoded(Certificate certificate, String fileName) throws Exception {
		StringWriter sw = new StringWriter();
		try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
			jpw.writeObject(certificate);
		}
		String pem = sw.toString();
		Path path = Paths.get(fileName);
		Path parent = path.getParent();
		if (parent != null && Files.notExists(parent)) {
			Files.createDirectories(parent);
		}
		Files.write(path, pem.getBytes());
	}

	private record TrustedCertificateHolder(Certificate certificate, String alias) {
	}

}
