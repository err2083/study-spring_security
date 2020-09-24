# 스프링 시큐리티
인증 : 주체(principal)의 신원(identity)을 증명하는 과정

주체 : 유저, 기기, 시스템 등

주체는 자신을 인증해달라고 신원 증명 정보(credential) 을 제시 주로 패스워드를 의미한다.

인가 : 인증을 마친 유저에게 권한을 부여하는 과정

접근통제 : 애플리케이션 리소스에 접근하는 행위

## 1. URL 접근 보안하기
스프링 시큐리티는 HTTP 요청에 서블릿 필터를 적용해 보안을 처리하는데,
AbstractSecurityWebApplicationInitializer 라는 베이스 클래스를 상속하면 편리하게 필터를 등록하고
구성 내용이 자동으로 감지하게 할 수 있습니다.

또한 WebSecurityConfigurerAdapter 라는 구성 어댑터에 준비된 다양한 configure() 메서드를 이용하면
웹 애플리케이션 보안을 쉽게 구성할수 있습니다.
* 폼 기반 로그인 서비스 : 유저가 애플리케이션에 로그인하는 기본 폼 페이지를 제공
* HTTP 기본 인증 : 요청 헤더에 표시된 HTTP 기본 인증 크레덴셜을 처리
* 로그아웃 서비스 : 유저를 로그아웃시키는 핸들러 제공
* 익명 로그인 : 익명 유저도 주체를 할당하고 권한을 부여하게 할수 있음
* 서블릿 API 연계 : 표준 서블릿 API를 이용해 보안 정보에 접근
* CSFR : 사이트 간 요청 위조 방어요 토큰 생성, HttpSession에 보관
* 보안 헤더 : 보안이 적용된 패키지에 대해 캐시를 해제하는 혀애로 다양한 보안 기능 제공

이러한 보안 서비스를 등록하면 특정 접근 권한을 요구하는 URL 패턴을 지정할수 있습니다.
유저는 이러한 보안이 적용된 URL에 접근하려면 로그인을 해주어야 합니다.

먼저 Config 파일을 만들어 보안을 구성합니다.    
```java
@Configuration
@EableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
} 
```
이렇게 설정만 해주어도 서버를 띄우면 로그인 페이지를 보실수 있습니다. 좀더 자세히 살펴보면

다음은 WeSecurityConfigurerAdapter 클래스에 있는 configure(HttpSecurity http) 메서드 입니다.
```java
public abstract class WebSecurityConfigurerAdapter implements WebSecurityConfigurer<WebSecurity> {
    protected void configure(HttpSecurity http) throws Exception {
        ((HttpSecurity)((HttpSecurity)((AuthorizedUrl)http
            .authorizeRequests()
            .anyRequest()).authenticated().and())
            .formLogin().and())
            .httpBasic();
    }
}
```
이는 기본적으로 anyRequest().authenticated()해서 매법 요청이 들어올때마다 인증을 받도록 강제합니다.
또한 httpBasic, formLogin 기능을 기본적으로 켜서 따로 로그인 페이지를 만들어 지정하지 않아도 기본 로그인
페이지를 보이도록 구성되어 있습니다.

그럼 더 강력한 URL 접근 규칙을 정의해보겠습니다.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("err2083@github.com").password("password").authorities("USER")
                .and()
                .withUser("admin@github.com").password("password").authorities("USER", "ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/todos*").hasAuthority("USER")
                .antMatchers(HttpMethod.DELETE, "/todos*").hasAuthority("ADMIN")
                .and()
                .formLogin()
                .and()
                .csrf()
                .disable();
    }
}
```
configure(HttpSecurity http) 메서드를 오버라이드하면 더 정교하게 인가 규칙을 적용할수 있습니다.
URL 접근 보안은 authorizeRequests() 부터 시작되며 여러 가지 매체를 이용해 규칙을 정할수 있습니다.
위 예제를 보면 "/todos" URL은 USER 권한을 가진 유저만 접근할수 있고, Http 메서드가 DELETE 인 요청은
ADMIN 권한을 가진 유저만 실행할수 있습니다.
인증 서비스는 configure(AuthenticationManagerBuilder auth) 메서드를 통해 구성합니다.
스프링 시큐리티는 DB 를 조회하여 유저를 인증하는 여러가지 방법을 지원합니다.

### CSFR 공격 방어
CSFR 방어 기능은 CSFR 공격에 노출될 위험이 있으니 기본 설정 그래도 두는것이 좋지만 필요시 .disable() 를 통해 작동 해제 할 수 있습니다.
CSFR 방어 기능이 작동하게 되면 스프링 시큐리티는 CsrfTokenRepository 인터페이스의 구현체를 이용해 토큰 값을 생성/보관하는 CsfrFilter를
보안 필터 목록에 추가합니다. 기본 구현체인 HttpSessionCsrfTokenRepository 클래스는 생성한 토큰을 HttpSession에 저장하며
CookieCsrfTokenRepository 클래스는 쿠키에 토큰을 저장합니다. repository는 csrfTokenRepository() 메서드를 이용하여 
교체할수 있습니다. 
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        HttpSessionCsrfTokenRepository repo = new HttpSessionCsrfTokenRepository();
        repo.setSessionAttributeName("csrf_token");
        repo.setParameterName("csrf_token");
        
        http.csrf().csrfTokenRepository(repo);
    }
}
```
csrf 방어 기능이 켜진 상태에서 CSRF 토큰을 서버에 재전송 해야만 정상 처리가 됩니다.
보통 페이지 상단에 taglib 를 선언하여 스프링 시큐리티가 CsrfRequestDataValueProcessor 클래스를 등록하고 
알아서 넣어줍니다.

## 2. 웹 애플리케이션 로그인하기
스프링 시큐리티는 로그인 폼을 지닌 기본페이지를 제공하지만 이를 개발자 취향에 맞게 할수도 있습니다.
또한 HTTP 요청 헤더에 포함된 기본 인증 크레덴셜 처리 기능 역시 구현되어있습니다.
그리고 익명 로그인, 자동 로그인(remember-me) 서비스도 제공해줍니다.
먼저 기본 보안 구성을 끄겠습니다. (가급적 전부다 끄지 말고 httpBasic().dsiable() 처럼 기능단위로 해체하세요)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public SecurityConfig() {
        super(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // (1)
        http.securityContext()
                .and()
                .exceptionHandling();
        // (2)
        http.servletApi();
    }
}
```
(1)예외 처리나 보안 컨텍스트 연계 등 스프링 시큐리티의 필수 기능은 인증 기능을 활성화하기 전에 켭니다.
(2)서블릿 API 연계 기능도 켜놔야 HttpServletRequest 에 있는 메서드를 이용해 뷰에서 뭔가를 체크할수 있습니다.

### HTTP 기본 인증
HTTP 기본 인증은 httpBasic() 메서드로 구성합니다. 이를 적용하면 브라우저는 로그인 대화상자를 띄우거나 특정 로그인페이지
로 이동시켜 로그인을 유도합니다. (HTTP 기본 인증과 폼 기반 로그인을 동시에 활성화 하면 폼 기반 로그인이 우선 적용됩니다.)

### 폼 기반 로그인
formLogin() 메서드로 폼 기반 로그인 서비스를 구성하면 유저가 로그인 정보를 입력하는 폼 페이지가 자동으로 렌더링 됩니다.
커스텀 로그인 페이지를 구성하고 싶다면 loginPage(URL) 메서드를 통해 설정합니다.
여기서 유저가 로그인응 성공할시 컨텍스트 루트로 리다이렉트 되는데 이를 따로 설정하고 싶다면
.defaultSuccessUrl(URL) 메서드를 통해 설정합니다.
비슷하기 로그인이 실패한 경우 첫 로그인 페이지로 돌아가고 에러 메세지가 표시되는데 커스텀 로그인 페이지를 지정하고 싶다면
failureUrl(URL) 메서드를 통해 설장합니다.

### 로그아웃 서비스
로그아웃 기능은 logout() 메서드로 구성합니다. 기본 URL은 /logout 이며 POST 요청일 경우에만 작동합니다.
로그아웃 유저는 기본 경로인 컨텍스트 루트로 이동하는데 다른 URL 로 보내고 싶으면 logoutSuccessUrl() 메서드에 지정합니다.
여기서 만일 유저가 뒤로가기를 하면 브라우저가 페이지를 캐시하기 때문에 로그인이 되어집니다. 이를 방지하게 위해
headers() 메서드로 보안 헤더를 활성하 해주면 브라우저가 더 이상 페이지를 캐시하지 않습니다.

### 익명 로그인 구현하기
익명 로그인 서비스는 anonymous() 메서드에 유저명(기본값은 anonymousUser)과 익명 유저(기본값은 ROLE_ANONYMOUS)의
권한을 지정합니다.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // (1)
        http.anonymous()
            .principal("guest")
            .authorities("ROLE_GUEST");
    }
}
```

### 리멤버 미 기능
이 메서드는 유저명, 패스워드, 리멤버 미 만료 시각, 개인키를 하나의 토큰으로 인코딩해서 유저 브라우저 쿠키에 저장합니다.
그후 웹 애플리케이션에 재접속하면 이 토큰값을 가져와 유저를 자동 로그인 시킵니다.

## 3. 유저 인증하기
스프링 시큐리티에서는 하나 이상의 AuthenticationProvider(인증 공급자) 를 이용해 인증을 수행합니다.
어느 하나의 공급자라도 실패를 반환하면 로그인할수 없게 됩니다.
대부분의 인증 공급자는 유저 세부를 보관한 저장소(memory, RDBMS, LDAP) 에서 정보를 가져와 대조합니다.
유저 세부를 저장할때는 암호화하여 저장하고, 이를 위해 스프링 시큐리티는 다양한 알고리즘(MD5, SHA)을 지원합니다.
유저가 로그인할때마다 저장소에서 가져오면 애플리케이션 성능이 낮아집니다. 그래서 스프링 시큐리티는 이러한 오버헤드를 줄이고자
로컬 메모리와 저장 공간에 캐시하는 기능을 제공합니다.

### 인메모리 방식으로 유저 인증하기
유저수가 적고, 정보를 수정할 일이 거의없는 경우에 괜찮은 방법입니다.
imMemoryAuthentication() 메서드 다음에 한사람씩 연결하여 유저를 지정합니다.
````java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("err2083@github.com").password("{noop}password").authorities("USER")
                .and()
                .withUser("admin@github.com").password("{noop}password").authorities("USER", "ADMIN")
                .and()
                .withUser("starlight@github.com").password("{noop}unknown").disabled(true).authorities("USER");
    }
}
````

### DB 조회 결과에 따라 유저 조회하기
스프링 시큐리티는 SQL을 실행하여 유저를 조회하는 기능을 지원합니다.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource())
               .usersByUsernameQuery("SELECT username, password FROM member WHERE username = ?")
               .authoritiesByUsernameQuery("query");
        }
}
```

### 패스워드 암호화하기
스프링 시큐리티는 패스워드를 단순 평문이 아닌 암호화로 저장하는 기능을 제공해줍니다.
````java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
        
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
               .passwordEncoder(passwordEncoder())
               .dataSource(dataSource());
        }
}
````

### LDAP 저장소 조회 결과에 따라 유저 인증하기
LDAP??

### 유저 세부 캐시하기
먼저 캐시기능을 제공하는 구현체를 선택하야합니다. 스프링에는 Ehcache가 기본으로 내장되어있어 클래스 패스 루트에
ehcache.xml 을 작성해 사용할 수 있습니다.
````xml
<ehcache>
    <diskStore path="java.io.tmpdir"/>

    <defaultCache
            maxElementsInMemory="1000"
            eternal="false"
            timeToIdleSeconds="120"
            timeToLiveSeconds="120"
            overflowToDisk="true"
    />

    <cache name="userCache"
           maxElementsInMemory="100"
           eternal="false"
           timeToIdleSeconds="600"
           timeToLiveSeconds="3600"
           overflowToDisk="true"
    />
</ehcache>
````
기본 캐시와 유저 세뷰용 캐시를 각각 구성했습니다. 유저 세부용 캐시는 최대 100명의 유저를 캐시하며(maxElementsInMemory="100")
이를 초과하면 디스크로 옮깁니다(overflowToDisk="true") 캐시유저는 10분 동안(timeToIdleSeconds="600") 사용이 없거나
생성 후(timeToLiveSeconds="3600") 1시간이 지나면 만료됩니다.

스프링 시큐리티는 ehCacheBasedUserCache와 스프링 캐시 추상체를 이용하는 SpringCacheBasedUserCache
이렇게 두개의 UserCache 인터페이스 구현체를 제공합니다.
먼저 캐시 매니저를 빈으로 등록합니다.
```java
@Configuration
public class CacheConfig {

    @Bean
    public EhCacheCacheManager cacheManager() {
        EhCacheCacheManager cacheManager = new EhCacheCacheManager();
        cacheManager.setCacheManager(ehCacheManager().getObject());
        return cacheManager;
    }
    
    @Bean
    public EhCacheManagerFactoryBean ehCacheManager() {
        return new EhCacheManagerFactoryBean();
    }
}
```
캐시 매니저를 구성한다음 SpringCacheBasedUserCache 클래스를 구성합니다.
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
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
```

