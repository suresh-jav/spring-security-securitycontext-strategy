package dev.sk.springsecuritysecuritycontextstrategy;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

@SpringBootApplication
public class SpringSecuritySecuritycontextStrategyApplication {
    @Configuration
//    @EnableWebSecurity(debug = true)
    @EnableWebSecurity
    static class SecurityConfig{

        @Autowired
        CustomAuth customAuth;
        @Bean
        SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception{
            httpSecurity.authorizeRequests(x->x.anyRequest().authenticated());
            httpSecurity.formLogin(Customizer.withDefaults());
            return httpSecurity.build();
        }
        @Bean
        public AuthenticationManager test(HttpSecurity httpSecurity)throws Exception{
            AuthenticationManagerBuilder authenticationManagerBuilder =
                    httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
            authenticationManagerBuilder.authenticationProvider(customAuth);
            return authenticationManagerBuilder.build();
        }
        @Bean
        public InitializingBean initializingBean(){
            return ()-> SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
        }
    }

    @Configuration
    @EnableAsync
    static  class ProjectConfig{

        String tmp_username = "admin";
        String tmp_password = "12345";
        @Bean
        public PasswordEncoder passwordEncoder(){
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }
        @Bean
        public UserDetailsService userDetailsService(){
            UserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
            userDetailsManager.createUser(
                    User.withUsername(tmp_username).password(bcryptEncode(tmp_password)).build()
            );
            return userDetailsManager;
        }

        private String bcryptEncode(final String passwd){
            return "{bcrypt}"+ new BCryptPasswordEncoder().encode(passwd);
        }

    }
    @Configuration
    static class CustomAuth implements AuthenticationProvider {

        @Autowired
        UserDetailsService userDetailsService;
        @Autowired
        PasswordEncoder passwordEncoder;
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            String uname = authentication.getName();
            try{
                //In case, User not found it'll raise Exception
                UserDetails userDetails = userDetailsService.loadUserByUsername(uname);

                if (!passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())){
                    throw new BadCredentialsException("");
                }
                return new UsernamePasswordAuthenticationToken(uname,authentication.getCredentials().toString(), List.of());

            }catch (Exception exception){
                System.err.println("Invalid Username/Password");
                throw new BadCredentialsException("Invalid Username/Password");
            }
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }

    @RestController
    static class MyController{
        @RequestMapping("/")
        @Async
        public Future<String> main(Authentication authentication){
            System.out.println("==========");
            System.out.println(authentication.getName());
            System.out.println(CompletableFuture.completedFuture("Hello"));
//            return "Hello, " + authentication.getName();
            return CompletableFuture.completedFuture("Hello");
        }
    }
    public static void main(String[] args) {
        SpringApplication.run(SpringSecuritySecuritycontextStrategyApplication.class, args);
    }

}
