package org.example.secure.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


public class JWKSGenerator {
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		// Generate RSA private and public keys
		KeyPair keyPair = generateRSAKeyPair();

		// Extract modulus (n) and exponent (e) in Base64URL format
		Map<String, String> jwkAttributes = getJWKAttributes((RSAPublicKey) keyPair.getPublic());

		// Create JWKS JSON structure
		String kid = "your-key-id";
		Map<String, Object> jwks = createJWKS(jwkAttributes, kid);

		// Base64 encode the private and public keys
		String base64PrivateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
		String base64PublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

		System.out.println("Private Key (Base64): " + base64PrivateKey);
		System.out.println("Public Key (Base64): " + base64PublicKey);

		// Convert JWKS to JSON string
		ObjectMapper mapper = new ObjectMapper();
		String jwksJson = mapper.writeValueAsString(jwks);
		System.out.println("JWKS JSON: " + jwksJson);
	}

	private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		return keyPairGenerator.generateKeyPair();
	}

	private static Map<String, String> getJWKAttributes(RSAPublicKey publicKey) {
		Map<String, String> jwkAttributes = new HashMap<>();
		jwkAttributes.put("n", base64UrlEncode(publicKey.getModulus().toByteArray()));
		jwkAttributes.put("e", base64UrlEncode(publicKey.getPublicExponent().toByteArray()));
		return jwkAttributes;
	}

	private static Map<String, Object> createJWKS(Map<String, String> jwkAttributes, String kid) {
		Map<String, Object> jwks = new HashMap<>();
		Map<String, Object> key = new HashMap<>();
		key.put("kty", "RSA");
		key.put("alg", "RS256");
		key.put("use", "sig");
		key.put("kid", kid);
		key.putAll(jwkAttributes);
		jwks.put("keys", new Object[]{key});
		return jwks;
	}

	private static String base64UrlEncode(byte[] data) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
	}
}
