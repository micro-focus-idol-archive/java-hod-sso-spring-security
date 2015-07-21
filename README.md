# HP Haven OnDemand SSO for Spring Security
Java library for working with HP Haven OnDemand SSO

## Usage
The library is available from the central Maven repository.

    <dependency>
        <groupId>com.hp.autonomy.hod</groupId>
        <artifactId>hod-sso-spring-security</artifactId>
        <version>0.1.1</version>
    </dependency>
    
## Setup
Below is a partial example configuration. In addition, a Spring MVC Controller or equivalent will need to expose the two
methods on HodAuthenticationRequestService to an HTTP endpoint.

    @Configuration
    @EnableWebSecurity
    public class SecurityConfigurationExample extends WebSecurityConfigurerAdapter {
        public static final String AUTHENTICATE_PATH = "/authenticate"; // 
        public static final String SSO_ENTRY_PAGE = "/sso"; // url for your SSO ajax page
    
        @Autowired
        private TokenRepository tokenRepository;
    
        @Autowired
        private AuthenticationService authenticationService;
    
        @Autowired
        @Override
        public void configureGlobal(final AuthenticationManagerBuilder builder) throws Exception {
            builder.authenticationProvider(ssoAuthenticationProvider());
        }
    
        @Override
        public void configure(final HttpSecurity http) throws Exception {
            http
                .exceptionHandling()
                    .authenticationEntryPoint(buildEntryPoint(new SsoAuthenticationEntryPoint(SSO_ENTRY_PAGE)))
                    .accessDeniedPage("/your-error-page")
                    .and()
                .addFilterAfter(ssoAuthenticationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .logout()
                    .disable();
        }
    
        @Bean
        public HodAuthenticationProvider ssoAuthenticationProvider() {
            return new HodAuthenticationProvider(tokenRepository, "ROLE_MYROLE", authenticationService);
        }
    
        @Bean
        public SsoAuthenticationFilter ssoAuthenticationFilter() throws Exception {
            final SsoAuthenticationFilter authenticationFilter = new SsoAuthenticationFilter(AUTHENTICATE_PATH);
            authenticationFilter.setAuthenticationManager(authenticationManager());
            return authenticationFilter;
        }
        
        @Bean
        public HodAuthenticationRequestService hodAuthenticationRequestService() {
            return new HodAuthenticationRequestServiceImpl(configService(), authenticationService(), unboundTokenService());
        }
    
        @Bean
        public UnboundTokenService unboundTokenService() {
            return new UnboundTokenServiceImpl(authenticationService(), configService());
        }

    }

# Is it any good?
Yes

## License
Copyright 2015 Hewlett-Packard Development Company, L.P.

Licensed under the MIT License (the "License"); you may not use this project except in compliance with the License.