package light.star.study.config;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //    // ## 1.
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("err2083@github.com").password("{noop}password").authorities("USER")
//                .and()
//                .withUser("admin@github.com").password("{noop}password").authorities("USER", "ADMIN");
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//
//        HttpSessionCsrfTokenRepository repo = new HttpSessionCsrfTokenRepository();
//        repo.setSessionAttributeName("csrf_token");
//        repo.setParameterName("csrf_token");
//
//        http.authorizeRequests()
//                .antMatchers("/todos*").hasAuthority("USER")
//                .antMatchers(HttpMethod.DELETE, "/todos*").hasAuthority("ADMIN")
//                .and()
//                .formLogin()
//                .and()
//                .csrf()
//                .csrfTokenRepository(repo);
//    }

//    // ## 2.
//    public SecurityConfig() {
//        super(true);
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.securityContext()
//                .and()
//                .exceptionHandling();
//
//        http.servletApi();
//
//        http.servletApi();
//
//        http.formLogin()
//                .loginPage("/login.jsp")
//                .defaultSuccessUrl("/study")
//                .failureUrl("login.jsp?error=true");
//
//        http.logout()
//                .logoutSuccessUrl("/logout-success.jsp")
//                .and()
//                .headers();
//
//        http.anonymous()
//                .principal("guest")
//                .authorities("ROLE_GUEST");
//
//        http.rememberMe();
//    }

//    // ## 3.
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("err2083@github.com").password("{noop}password").authorities("USER")
//                .and()
//                .withUser("admin@github.com").password("{noop}password").authorities("USER", "ADMIN")
//                .and()
//                .withUser("starlight@github.com").password("{noop}unknown").disabled(true).authorities("USER");
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.jdbcAuthentication().dataSource(dataSource())
//                .usersByUsernameQuery("SELECT username, password FROM member WHERE username = ?")
//                .authoritiesByUsernameQuery("query");
//    }

//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.jdbcAuthentication()
//                .passwordEncoder(passwordEncoder())
//                .dataSource(dataSource());
//    }

    private final CacheManager cacheManager;

    @Bean
    public SpringCacheBasedUserCache userCache() throws Exception {
        Cache cache = cacheManager.getCache("userCache");
        return new SpringCacheBasedUserCache(cache);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .userCache(userCache());
    }
}
