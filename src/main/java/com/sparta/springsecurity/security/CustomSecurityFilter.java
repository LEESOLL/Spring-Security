package com.sparta.springsecurity.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class CustomSecurityFilter extends OncePerRequestFilter {

    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = request.getParameter("username"); // getParameter 로 클라이언트에서 넘어오는 파라미터 값을 가져올 수 있다.
        String password = request.getParameter("password");

        System.out.println("username = " + username);
        System.out.println("password = " + password);
        System.out.println("request.getRequestURI() = " + request.getRequestURI());

        if(username != null && password != null && (request.getRequestURI().equals("/api/user/login") || request.getRequestURI().equals("/api/test-secured"))) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            //비밀번호 확인
            if (!passwordEncoder.matches(password, userDetails.getPassword())) { //평문으로 받은 password를 암호화 해서 userDetails에 저장된 암호화 된 비밀번호와 같은지 확인한다
                throw new IllegalAccessError("비밀번호가 일치하지 않습니다.");
            }

            //인증 객체 생성 및 등록
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()); // 위에서 비밀번호에 대한 검증이 끝났기 때문에, credentials 부분에는 값을 넣어주지 않음
            context.setAuthentication(authentication); // context 안에 authentication 객체를 집어넣음

            SecurityContextHolder.setContext(context); // 컨텍스트 홀더에 컨텍스트를 집어넣음
        }

        filterChain.doFilter(request, response); // 위의 과정을 통과하고 나면 다음 필터로 넘어간다.
    }
}
