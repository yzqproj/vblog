package org.sang.config;

import cn.hutool.core.util.StrUtil;
import lombok.extern.slf4j.Slf4j;
import org.sang.bean.User;
import org.sang.utils.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author yanni
 */
@Slf4j
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    private Integer tokenExpireTime;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, Integer tokenExpireTime) {
        super(authenticationManager);
        this.tokenExpireTime = tokenExpireTime;
    }

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String token = request.getHeader(SecurityConstant.TOKEN);
        if (StrUtil.isBlank(token)) {
            token = request.getParameter(SecurityConstant.TOKEN);
        }
        boolean notValid = StrUtil.isBlank(token) || (!token.startsWith(SecurityConstant.TOKEN_SPLIT));
        if (notValid) {
            chain.doFilter(request, response);
            return;
        }
        try {
            //UsernamePasswordAuthenticationToken ?????? AbstractAuthenticationToken ?????? Authentication
            //????????????????????????????????????????????????????????????????????? UsernamePasswordAuthenticationToken??????(Authentication)???
            UsernamePasswordAuthenticationToken authentication = getAuthentication(token, response);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            e.printStackTrace();
        }

        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String token, HttpServletResponse response) {

        String username = null;
        List<GrantedAuthority> authorities = new ArrayList<>();


        try {
            //??????token
             username= JwtUtil.getUserName(token);
            logger.info("username???" + username);
            //????????????
            String authority = JwtUtil.getUserAuth(token);
            logger.info("authority???" + authority);
            if ( StringUtils.hasText(authority)) {
                authorities.add(new SimpleGrantedAuthority(authority));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (StrUtil.isNotBlank(username)) {
            //???????????? ??????password?????????null
            User principal = new User(username);
            return new UsernamePasswordAuthenticationToken(principal, null, authorities);
        }
        return null;
    }
}