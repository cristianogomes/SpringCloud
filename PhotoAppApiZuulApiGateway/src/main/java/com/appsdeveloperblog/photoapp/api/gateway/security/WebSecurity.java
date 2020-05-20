package com.appsdeveloperblog.photoapp.api.gateway.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    private Environment environment;

    public WebSecurity(Environment environment) {
        this.environment = environment;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.authorizeRequests()
            .antMatchers(environment.getProperty("api.url.path.actuator.zuul")).permitAll()
            .antMatchers(environment.getProperty("api.url.path.actuator.users")).permitAll()
            .antMatchers(environment.getProperty("api.url.path.h2console")).permitAll()
            .antMatchers(HttpMethod.POST, environment.getProperty("api.url.path.registration")).permitAll()
            .antMatchers(HttpMethod.POST, environment.getProperty("api.url.path.login")).permitAll()
            .anyRequest().authenticated()
            .and()
            .addFilter(new AuthorizationFilter(authenticationManager(), environment));

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}
