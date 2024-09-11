package org.example.secure.controllers;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@RestController
public class JwkSetController {
	private final JWKSet jwkSet;

	public JwkSetController(SslBundles sslBundles, JWKSource<SecurityContext> jwkSource) throws Exception {
		this.jwkSet = initJwkSet(sslBundles, jwkSource);
	}

	private static JWKSet initJwkSet(SslBundles sslBundles, JWKSource<SecurityContext> jwkSource) throws Exception {
		SslBundle sslBundle = sslBundles.getBundle("self-signed-demo-client");
		KeyStore keyStore = sslBundle.getStores().getKeyStore();
		String alias = sslBundle.getKey().getAlias();

		Certificate certificate = keyStore.getCertificate(alias);

		RSAKey selfSignedCertificatePublicKey = new RSAKey.Builder((RSAPublicKey) certificate.getPublicKey())
				.keyUse(KeyUse.SIGNATURE)
				.keyID(UUID.randomUUID().toString())
				.x509CertChain(Collections.singletonList(Base64.encode(certificate.getEncoded())))
				.build();

		List<JWK> jwks = new ArrayList<>();
		jwks.add(selfSignedCertificatePublicKey);

		JWKSelector jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
		jwks.addAll(jwkSource.get(jwkSelector, null));

		return new JWKSet(jwks);
	}

	@GetMapping("/jwks")
	public Map<String, Object> getJwkSet() {
		return this.jwkSet.toJSONObject();
	}

}
