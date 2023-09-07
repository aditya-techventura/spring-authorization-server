package sample.aot;

import java.util.concurrent.Callable;

import org.thymeleaf.expression.Lists;
import sample.web.AuthorizationConsentController;

import org.springframework.aot.hint.BindingReflectionHintsRegistrar;
import org.springframework.aot.hint.ExecutableMode;
import org.springframework.aot.hint.ReflectionHints;
import org.springframework.aot.hint.ResourceHints;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.web.jackson2.WebJackson2Module;
import org.springframework.security.web.jackson2.WebServletJackson2Module;
import org.springframework.security.web.server.jackson2.WebServerJackson2Module;
import org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod;

import static org.springframework.aot.hint.MemberCategory.DECLARED_FIELDS;
import static org.springframework.aot.hint.MemberCategory.INVOKE_DECLARED_CONSTRUCTORS;
import static org.springframework.aot.hint.MemberCategory.INVOKE_DECLARED_METHODS;

public class HintsRegistration implements RuntimeHintsRegistrar {
    private final BindingReflectionHintsRegistrar bindingRegistrar = new BindingReflectionHintsRegistrar();

    @Override
    public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
        try {
            ReflectionHints reflection = hints.reflection();
            reflection.registerMethod(Callable.class.getMethod("call"), ExecutableMode.INVOKE);
            reflection.registerType(Class.forName("org.springframework.web.servlet.handler.AbstractHandlerMethodMapping$EmptyHandler"), INVOKE_DECLARED_METHODS);
            reflection.registerType(ServletInvocableHandlerMethod.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
            reflection.registerType(OAuth2AuthorizationCodeRequestAuthenticationToken.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);

			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.server.authorization.jackson2.UnmodifiableListMixin"));

			// Thymeleaf
            reflection.registerType(AuthorizationConsentController.ScopeWithDescription.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
			reflection.registerType(Lists.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);

			// Security Jackson Modules
            reflection.registerType(CoreJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
            reflection.registerType(WebJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
            reflection.registerType(WebServerJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
            reflection.registerType(WebServletJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);
            reflection.registerType(OAuth2ClientJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);

//			reflection.registerType(OAuth2AuthorizationServerJackson2Module.class, DECLARED_FIELDS, INVOKE_DECLARED_CONSTRUCTORS, INVOKE_DECLARED_METHODS);


            // Jackson Mixins registration
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.DefaultOAuth2UserMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.DefaultOidcUserMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2AccessTokenMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2AuthenticationExceptionMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2AuthenticationTokenMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2AuthorizedClientMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2ErrorMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2RefreshTokenMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OAuth2UserAuthorityMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OidcIdTokenMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OidcUserAuthorityMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.client.jackson2.OidcUserInfoMixin"));
            bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.server.authorization.jackson2.OAuth2TokenFormatMixin"));

			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.jackson2.UnmodifiableSetMixin"));
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.jackson2.SimpleGrantedAuthorityMixin"));
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationRequestMixin"));
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.server.authorization.jackson2.UnmodifiableMapMixin"));
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.oauth2.server.authorization.jackson2.HashSetMixin"));

//			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.jackson2.UnmodifiableMapMixin"));


			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.jackson2.UsernamePasswordAuthenticationTokenMixin"));
			bindingRegistrar.registerReflectionHints(reflection, Class.forName("org.springframework.security.jackson2.UserMixin"));



            // Resources hints
            ResourceHints resources = hints.resources();
            resources.registerPattern("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql");
            resources.registerPattern("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql");
            resources.registerPattern("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql");
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }
}
