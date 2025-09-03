package com.example.springjwtcors.controller;

import com.example.springjwtcors.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

// @CrossOrigin // [1] 이렇게 풀수도 있긴한데...
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    // 로그인 해야 접속할 수 있는 경우
    // /api/auth/data
    @GetMapping("/data")
    public String data(Authentication authentication) {
        return "Hello " + authentication.getName();
    }

    // /api/auth/login
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.username(),
                        loginRequest.password()
                )
        ); // 실패하면 오류 403?
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = jwtUtil.createAccessToken(userDetails.getUsername());
        return ResponseEntity.ok(new LoginResponse(accessToken));
    }

    public record LoginRequest(String username, String password) { }

    public record LoginResponse(String accessToken) { }
}
