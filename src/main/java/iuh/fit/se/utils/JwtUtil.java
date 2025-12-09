package iuh.fit.se.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import iuh.fit.se.entities.auth.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.exp-minutes}")
    private int expMinutes;

    // Sinh token moi cho user
    public String generateToken(User user) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expMinutes * 60 * 1000);

        return Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getIdUser()) // add userId
                .claim("role", user.getRole().name())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                .compact();
    }

    // Lay email tu token
    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    // (Nguyen Sinh): Get userId
    public Long extractUserId(String token) {
        return Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret)))
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("userId", Long.class);
    }
}
