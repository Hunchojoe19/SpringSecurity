package com.hunchojoe.security.authController;

import com.hunchojoe.security.dto.request.AuthRequest;
import com.hunchojoe.security.dto.request.RegisterRequest;
import com.hunchojoe.security.dto.response.AuthenticationResponse;
import com.hunchojoe.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity <AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest){
        return ResponseEntity.ok(authService.register(registerRequest) );
    }
    @PostMapping("/authenticate")
    public ResponseEntity <AuthenticationResponse> authenticate(@RequestBody AuthRequest authRequest){
        return ResponseEntity.ok(authService.authenticate(authRequest) );
    }
}