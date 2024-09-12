package alexgr.jwt.utils;

import alexgr.jwt.user.Role;
import io.jsonwebtoken.Claims;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtTokenService {


    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey())
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean validateToken(String token, UserDetails userDetails) {

        final String username = extractUsername(token);
        if ((username.equals(userDetails.getUsername()) && !isTokenExpired(token))) {
            return true;
        } else {
            throw new JwtException("username name not equals or token has expired");
        }

    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public UserDetails extractUserDetails(String token) {
        Claims claims = extractAllClaims(token);
        String username = claims.getSubject();
        List<GrantedAuthority> authorities = ((List<?>) claims.get("roles")).stream()
                .map(role -> new SimpleGrantedAuthority((String) role))
                .collect(Collectors.toList());
        return new User(username, "", authorities);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token).getPayload();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private SecretKey getSignInKey() {
        String KEY = "f2e9ed03291b9e10bcf8c3915f2738fab05ef7d44e808f269a66b16d07dc6d91";
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(KEY));
    }

}
