package org.sang.config;

import lombok.extern.slf4j.Slf4j;
import org.sang.bean.User;
import org.sang.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.DigestUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

/**
 * @author sang
 * @date 2017/12/17
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().and().authorizeRequests()
                .antMatchers("/admin/category/all").authenticated()
                ///admin/**的URL都需要有超级管理员角色，如果使用.hasAuthority()方法来配置，需要在参数中加上ROLE_,如下.hasAuthority("ROLE_超级管理员")
                .antMatchers("/admin/**", "/reg").hasRole("超级管理员")
                .anyRequest().authenticated()//其他的路径都是登录后即可访问
                .and().formLogin()
                //登录成功后的返回结果
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    httpServletResponse.setContentType("application/json;charset=utf-8");

                    //登录成功后获取当前登录用户
                    User userDetail = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                    log.info("用户[{}]于[{}]登录成功!", userDetail.getUsername(), new Date());
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write("{\"status\":\"success\",\"msg\":\"登录成功\"}");
                    out.flush();
                    out.close();
                })
                //登录失败后的返回结果
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    httpServletResponse.setContentType("application/json;charset=utf-8");
                    String username = httpServletRequest.getParameter("username");
                    log.info("用户[{}]于[{}]登录失败,失败原因：[{}]", username, new Date(), httpServletResponse.getStatus());
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write("{\"status\":\"error\",\"msg\":\"登录失败\"}");
                    out.flush();
                    out.close();
                })
                //这里配置的loginProcessingUrl为页面中对应表单的 action ，该请求为 post，并设置可匿名访问
                //.loginProcessingUrl("/login")
                //.usernameParameter("username").passwordParameter("password").permitAll()
                .and()
                //前后端分离采用JWT 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //添加JWT过滤器 除已配置的其它请求都需经过此过滤器
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), 7))
                //退出登录
                .logout().permitAll().logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    if (authentication != null) {
                        log.info("用户[{}]于[{}]注销成功!", ((User) authentication.getPrincipal()).getUsername(), new Date());
                    }
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write("""
                            { "status":"error","msg":"注销成功"}
                            """);
                    out.flush();
                    out.close();
                }).and().csrf().disable().exceptionHandling().accessDeniedHandler(getAccessDeniedHandler());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/blogimg/**", "/index.html", "/static/**");
    }

    @Bean
    AccessDeniedHandler getAccessDeniedHandler() {
        return new AuthenticationAccessDeniedHandler();
    }
}