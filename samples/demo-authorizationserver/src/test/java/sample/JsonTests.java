/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.junit.jupiter.api.Test;
import sample.aot.HintsRegistration;

import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@SpringBootTest
public class JsonTests {

	@Autowired
	ObjectMapper objectMapper;

	@Test
	public void testJson() throws Exception {

		var gaList = new com.fasterxml.jackson.core.type.TypeReference<List<GrantedAuthority>>() {
		};
		var classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
		var securityModules = SecurityJackson2Modules.getModules(classLoader);
		this.objectMapper.registerModules(securityModules);
		this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

		this.objectMapper.registerModule(new SimpleModule(CoreJackson2Module.class.getName() + "-overrides", new Version(1, 0, 0, null, null, null)) {

			@Override
			public void setupModule(SetupContext context) {
				Class<?> unmodifiableRandomAccessList = null;
				try {
					unmodifiableRandomAccessList = Class.forName("java.util.Collections$UnmodifiableRandomAccessList");
					System.out.println("************************ LOADED java.util.Collections$UnmodifiableRandomAccessList ");

					for (var m : unmodifiableRandomAccessList.getDeclaredMethods()){
						System.out.println("********** METHOD -> " + m.getName());
					}

				} catch (ClassNotFoundException e) {
					System.out.println("************************ ERROR loading java.util.Collections$UnmodifiableRandomAccessList ");
				}

				if (unmodifiableRandomAccessList != null) {
					context.setMixInAnnotations(unmodifiableRandomAccessList, UnmodifiableListMixin.class);
				}


//				context.setMixInAnnotations(Collections.<Object>unmodifiableList(Collections.emptyList()).getClass(),
//						UnmodifiableListMixin.class);
//				context.setMixInAnnotations(Collections.<Object>unmodifiableCollection(Collections.emptyList()).getClass(),
//						UnmodifiableListMixin.class);

			}

		});

		var json = """

{
  "@class": "java.util.Collections$UnmodifiableMap",
  "java.security.Principal": {
    "@class": "org.springframework.security.authentication.UsernamePasswordAuthenticationToken",
    "authorities": [
      "java.util.Collections$UnmodifiableRandomAccessList",
      [
        {
          "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
          "authority": "ROLE_A"
        },
        {
          "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
          "authority": "ROLE_B"
        }
      ]
    ],
    "details": null,
    "authenticated": true,
    "principal": {
      "@class": "org.springframework.security.core.userdetails.User",
      "password": "password",
      "username": "user",
      "authorities": [
        "java.util.Collections$UnmodifiableSet",
        [
          {
            "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
            "authority": "ROLE_C"
          },
          {
            "@class": "org.springframework.security.core.authority.SimpleGrantedAuthority",
            "authority": "ROLE_D"
          }
        ]
      ],
      "accountNonExpired": true,
      "accountNonLocked": true,
      "credentialsNonExpired": true,
      "enabled": true
    },
    "credentials": "password"
  },
  "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest": {
    "@class": "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest",
    "authorizationUri": "http://localhost/oauth2/authorize",
    "authorizationGrantType": {
      "value": "authorization_code"
    },
    "responseType": {
      "value": "code"
    },
    "clientId": "client-1",
    "redirectUri": "https://example.com/callback-1",
    "scopes": [
      "java.util.Collections$UnmodifiableSet",
      [
        "openid",
        "scope1"
      ]
    ],
    "state": "state",
    "additionalParameters": {
      "@class": "java.util.Collections$UnmodifiableMap"
    },
    "authorizationRequestUri": "http://localhost/oauth2/authorize?response_type=code&client_id=client-1&scope=openid%20scope1&state=state&redirect_uri=https://example.com/callback-1",
    "attributes": {
      "@class": "java.util.Collections$UnmodifiableMap"
    }
  }
}
                    """;
//		var jsonNode = objectMapper.readTree(json);
//		var authoritiesJsonNode = readJsonNode(jsonNode, "authorities").traverse(objectMapper);
//		var authorities = objectMapper.readValue(authoritiesJsonNode, gaList);

		var authorities = parseMap(json, objectMapper);

		System.out.println("");
//		for (var ga : authorities)
//			System.out.println(ga.toString());

	}

	private Map<String, Object> parseMap(String data, ObjectMapper objectMapper) {
		try {
			return objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	@Configuration
	static class Config {

		@ImportRuntimeHints(HintsRegistration.class)
		@RegisterReflectionForBinding({
				OAuth2AccessTokenResponse.class,
				OAuth2AuthorizationRequest.class,
				DefaultOAuth2User.class,
				DefaultOidcUser.class,
				OAuth2TokenFormat.class,
				OidcIdToken.class,
				OidcUserInfo.class,
				OidcUserAuthority.class,
				OAuth2UserAuthority.class,
				SimpleGrantedAuthority.class,
				OAuth2LoginAuthenticationToken.class,
				OAuth2AuthorizationCodeRequestAuthenticationToken.class,
				OAuth2AuthenticationToken.class,
				UsernamePasswordAuthenticationToken.class,
				User.class,
				WebAuthenticationDetails.class
		})
		@Bean
		ObjectMapper objectMapper() {
			return new ObjectMapper();
		}

	}


}
