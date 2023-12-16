package com.example.demo.config;

import com.example.demo.config.oauth.PricipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

// 1. 코드받기(인증) 2. 엑세스 토큰 받기(권한)
// 3. 사용자 프로필 정보를 가져와서 4. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함.
// 4-2 (이메일, 전화번호, 이름, 아이디)쇼핑몰 -> (집주소), 백화점몰 -> (vip등급, 일반등급)
@Configuration
@EnableWebMvc
@EnableMethodSecurity(securedEnabled = true)
// 권한 설정을 해주는 어노테이션 securedEnabled = true로 되어있으면 컨트롤러에서 @Secured를사용해 권한을 설정해줄수 있다.
public class SecurityConfig { //스프링 3.0 이후 스프링 코드

    @Autowired
    private PricipalOauth2UserService pricipalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(
                config -> config.disable()
        );

        http.authorizeHttpRequests(authorize -> //요청 uri와 로그인한 계정의 권한이 일치하는지?
                        authorize
                                .requestMatchers("/user/**").authenticated() // .authenticated() 인증된 사용자
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER") // ./manager에 접속을 하기 위해서는 "ADMIN" 또는 "MANAGER"권한이 필요함
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                                .anyRequest().permitAll() // 나머지요청은 모두 허용
                )
                .formLogin(formLogin -> formLogin // 권한이 없는 이용자일 경우 로그인 페이지로 이동
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login") // login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행
                        .defaultSuccessUrl("/") //로그인이 완료되면 "/"주소로 이동
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/loginForm")// 구글 로그인이 완료된 뒤의 후처리가 필요함.

                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                        .userService(pricipalOauth2UserService)
                )// Tip: 구글로그인이 완료되면 코드를 받는게 X (엑세스토큰 + 사용자프로필정보 O)



                );

        return http.build();
    }
}

//@Configuration 스프링 3.0 이전 버전의 시큐리티 코드
//@EnableWebMvc
//public class SecurityConfig extends WebSecurityConfigurerAdapter{
//    @Override
//    protected void configure(HttpSecurity http) throws Exception{
//        http.csrf().disable();
//        http.authorizeHttpRequests()
//                .antMatchers("/user/**").authenticated()
//                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN')or hasRole('ROLE_MANAWGER')")
//                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
//                .anyRequest().permitAll();
//    }
//}