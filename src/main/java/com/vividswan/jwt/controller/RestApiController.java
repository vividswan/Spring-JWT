package com.vividswan.jwt.controller;

import com.vividswan.jwt.config.auth.PrincipalDetails;
import com.vividswan.jwt.model.User;
import com.vividswan.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){
        String lawPassword = user.getPassword();
        user.setPassword(bCryptPasswordEncoder.encode(lawPassword));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

    @GetMapping("api/v1/user")
    public String user(Authentication authentication){
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();

        return "user";
    }

    @GetMapping("api/v1/manager")
    public String manager(){
        return "manager";
    }

    @GetMapping("api/v1/admin")
    public String admin(){
        return "admin";
    }
}
