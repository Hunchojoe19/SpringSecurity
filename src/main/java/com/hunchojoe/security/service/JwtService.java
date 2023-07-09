package com.hunchojoe.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";


    private static final long JWTEXPIRATION = 86400000;


    private static final long REFRESHEXPIRATION = 604800000;

    public static String extractUserMail(String jwt) {
        return extractClaim(jwt, Claims:: getSubject);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userdetails){
       return buildToken(extraClaims, userdetails, JWTEXPIRATION);
    }

    public String generateToken(UserDetails userdetails){

        return generateToken(new HashMap<>(), userdetails);
    }
    public String generateRefreshToken(UserDetails userdetails){
        return buildToken(new HashMap<>(), userdetails, REFRESHEXPIRATION);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUserMail(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    private String buildToken(Map<String, Object> extraClaims, UserDetails userdetails, long expiration){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userdetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    public static <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private static Claims extractAllClaims(String jwt) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(jwt)
                .getBody();
    }

    private static Key getSigningKey() {
        byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
