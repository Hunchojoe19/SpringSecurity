package com.hunchojoe.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hunchojoe.security.dto.request.AuthRequest;
import com.hunchojoe.security.dto.request.RegisterRequest;
import com.hunchojoe.security.dto.response.AuthenticationResponse;
import com.hunchojoe.security.repo.UserRepo;
import com.hunchojoe.security.user.Role;
import com.hunchojoe.security.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepo userRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepo.save(user);
       var jwt = jwtService.generateToken(user);
       var refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .email(user.getEmail())
                .build();
    }

    public AuthenticationResponse authenticate(AuthRequest authRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(),
                        authRequest.getPassword()
                )

        );
        var user = userRepo.findByEmail(authRequest.getEmail()).orElseThrow(()-> new RuntimeException("User not found"));
        var jwt = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwt)
                .refreshToken(refreshToken)
                .email(user.getEmail())
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String userMail;
        if (authHeader == null || !authHeader.startsWith(("Bearer "))){
            return;
        }
        refreshToken = authHeader.substring(7);
        userMail = JwtService.extractUserMail(refreshToken);
        if (userMail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            var foundUser = this.userRepo.findByEmail(userMail).orElseThrow(()-> new RuntimeException("User not found"));
            if (jwtService.isTokenValid(refreshToken, foundUser)){
                var accessToken = jwtService.generateToken(foundUser);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .email(foundUser.getEmail())
                        .build();
                response.setHeader("Authorization", "Bearer " + accessToken);
                response.setHeader("RefreshToken", "Bearer " + refreshToken);
//                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }

            }
    }
}
