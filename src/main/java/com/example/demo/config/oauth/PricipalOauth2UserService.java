package com.example.demo.config.oauth;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.config.oauth.provider.FacebookUserInfo;
import com.example.demo.config.oauth.provider.GoogleUserInfo;
import com.example.demo.config.oauth.provider.OAuth2UserInfo;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PricipalOauth2UserService extends DefaultOAuth2UserService {
    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest : " + userRequest);
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration()); //getClientRegistration으로 어떤 Oauth로 로그인 했는지 확인 가능
        System.out.println("getAccessToken : " + userRequest.getAccessToken().getTokenValue());


        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 우리가 구글 로그인 버튼을 클릭 -> 구글로그인창 -> 로그인을 완료 -> code를 리턴(OAuth-client) -> AccessToken 요청
        //userRequest 정보 -> 회원프로필 받아야함(loadUser함수) -> 구글로부터 회원프로필을 받아준다.
        System.out.println("getAttributes:" + oAuth2User.getAttributes());
        System.out.println("oAuth2User" + oAuth2User);

        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")){
            System.out.println("구글 로그인");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
            System.out.println("페이스북 로그인");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());

        } else {
            System.out.println("우리는 페이스북과 구글만 지원합니다");
        }
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = bCryptPasswordEncoder.encode("1234");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        }
        PrincipalDetails principalDetails = new PrincipalDetails(userEntity, oAuth2User.getAttributes());
        System.out.println("principalDetails : " + principalDetails);
        return principalDetails;
    }
}
