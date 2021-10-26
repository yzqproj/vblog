package org.sang.controller;

import cn.hutool.core.util.StrUtil;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import org.sang.bean.RespBean;
import org.sang.bean.User;
import org.sang.service.UserService;
import org.sang.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by sang on 2017/12/17.
 */
@RestController
public class LoginRegController {

    @Autowired
    UserService userService;

    @RequestMapping("/login_error")
    public RespBean loginError() {
        return new RespBean("error", "登录失败!");
    }

    @RequestMapping("/login_success")
    public RespBean loginSuccess() {
        return new RespBean("success", "登录成功!");
    }

    /**
     * 如果自动跳转到这个页面，说明用户未登录，返回相应的提示即可
     * <p>
     * 如果要支持表单登录，可以在这个方法中判断请求的类型，进而决定返回JSON还是HTML页面
     *
     * @return
     */
    @RequestMapping("/login_page")
    public RespBean loginPage() {
        return new RespBean("error", "尚未登录，请登录!");
    }

    @PostMapping("/login")
    public HashMap<String,Object> loginPost(String username, String password) {
        if (StrUtil.isNotEmpty(username) && StrUtil.isNotEmpty(password)) {
            QueryWrapper<User> queryWrapper = new QueryWrapper<>(
                    new User(username));
            UserDetails adminUser = userService.loadUserByUsername(username);
            String token = JwtUtil.sign(username, String.valueOf(adminUser.getAuthorities()));
            HashMap<String,Object> res=new HashMap<>(1);
            res.put("token",token);
            return res;
        } else {
            return null;
        }

    }

    @PostMapping("/reg")
    public RespBean reg(User user) {
        int result = userService.reg(user);
        if (result == 0) {
            //成功
            return new RespBean("success", "注册成功!");
        } else if (result == 1) {
            return new RespBean("error", "用户名重复，注册失败!");
        } else {
            //失败
            return new RespBean("error", "注册失败!");
        }
    }
}
