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