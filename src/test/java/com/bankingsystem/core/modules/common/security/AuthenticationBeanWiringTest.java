package com.bankingsystem.core.modules.common.security;

import com.bankingsystem.core.features.accesscontrol.domain.repository.RoleRepository;
import com.bankingsystem.core.features.auth.application.impl.AuthServiceImpl;
import com.bankingsystem.core.features.auth.domain.repository.SessionRepository;
import com.bankingsystem.core.features.auth.domain.repository.UserRepository;
import com.bankingsystem.core.features.auth.domain.repository.VerificationTokenRepository;
import com.bankingsystem.core.features.system.application.EmailService;
import com.bankingsystem.core.modules.common.config.AppProperties;
import com.bankingsystem.core.modules.common.config.AuthClockConfiguration;
import com.bankingsystem.core.modules.common.config.JwtProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AuthenticationBeanWiringTest {

    @Test
    void authenticationBeansStartWithoutDatabaseConnections() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.addBeanFactoryPostProcessor(beanFactory -> makeSecurityInfrastructureLazy(beanFactory));
            context.register(TestConfiguration.class, AuthClockConfiguration.class, SecurityConfig.class, JwtUtils.class, JwtAuthFilter.class,
                    AuthServiceImpl.class);
            context.refresh();

            assertThat(context.getBean(JwtUtils.class)).isNotNull();
            assertThat(context.getBean(JwtAuthFilter.class)).isNotNull();
            assertThat(context.getBean(AuthServiceImpl.class)).isNotNull();
            assertThat(context.getBean(java.time.Clock.class)).isNotNull();
            assertThat(context.getBean("loginAuthenticationManager", AuthenticationManager.class)).isNotNull();
            assertThat(context.getBeansOfType(AuthenticationProvider.class)).containsOnlyKeys("authenticationProvider");
        }
    }

    private static void makeSecurityInfrastructureLazy(ConfigurableListableBeanFactory beanFactory) {
        Stream.of("securityFilterChain", "authenticationProvider", "passwordEncoder", "authenticationManager")
                .filter(beanFactory::containsBeanDefinition)
                .forEach(name -> beanFactory.getBeanDefinition(name).setLazyInit(true));
    }

    @Configuration(proxyBeanMethods = false)
    static class TestConfiguration {

        @Bean
        JwtProperties jwtProperties() {
            JwtProperties properties = new JwtProperties();
            properties.setSecret("test-jwt-secret-012345678901234567890123");
            properties.setExpirationMs(86_400_000L);
            properties.setIssuer("bank-core");
            properties.setAudience("bank-core-api");
            return properties;
        }

        @Bean
        UserRepository userRepository() {
            return mock(UserRepository.class);
        }

        @Bean
        RoleRepository roleRepository() {
            return mock(RoleRepository.class);
        }

        @Bean
        PasswordEncoder passwordEncoder() {
            return mock(PasswordEncoder.class);
        }

        @Bean
        SessionRepository sessionRepository() {
            return mock(SessionRepository.class);
        }

        @Bean
        VerificationTokenRepository verificationTokenRepository() {
            return mock(VerificationTokenRepository.class);
        }

        @Bean
        EmailService emailService() {
            return mock(EmailService.class);
        }

        @Bean
        AppProperties appProperties() {
            return new AppProperties();
        }

        @Bean
        UserDetailsServiceImpl userDetailsService(UserRepository userRepository) {
            return new UserDetailsServiceImpl(userRepository);
        }
    }
}
