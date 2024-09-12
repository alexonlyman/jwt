package alexgr.jwt.user_service;

import alexgr.jwt.repo.UserRepo;
import alexgr.jwt.user.UserEntity;
import alexgr.jwt.utils.AuthenticationResponse;
import alexgr.jwt.utils.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.security.auth.login.AccountLockedException;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 6;

    private final UserRepo userRepo;
    private final JwtTokenService tokenService;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;


    public AuthenticationResponse register(UserEntity user) {
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail(user.getEmail());
        userEntity.setPassword(user.getPassword());
        userEntity.setUsername(user.getUsername());
        userEntity.setRole(user.getRole());
        logger.info("user " + userEntity.getUsername() + " role " + userEntity.getRole().getName());
        userRepo.save(userEntity);
        String token = tokenService.generateToken(userEntity);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }


    public AuthenticationResponse login(UserEntity user) throws AccountLockedException {
        UserDetails userDetails = userService.loadUserByUsername(user.getUsername());
        UserEntity userEntity = userRepo.findUserEntityByUsername(userDetails.getUsername());

        if (userEntity == null) {
            throw new BadCredentialsException("Invalid username or password");
        }

        if (!passwordEncoder.matches(user.getPassword(), userDetails.getPassword())) {
            handleFailedLoginAttempt(userEntity);
            throw new BadCredentialsException("Invalid username or password");
        }

        if (!userDetails.isAccountNonLocked()) {
            throw new AccountLockedException("Account is locked or doesn't exist.");
        }

        resetFailedAttempts(userEntity);
        String token = tokenService.generateToken(userDetails);
        logger.info("user role " + userDetails.getAuthorities().toString());
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    private void handleFailedLoginAttempt(UserEntity user) {
        int newFailedAttempt = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(newFailedAttempt);
        if (newFailedAttempt > MAX_FAILED_ATTEMPTS) {
            user.setAccountNonLocked(false);
        }
        userRepo.save(user);
    }

    private void resetFailedAttempts(UserEntity user) {
        user.setFailedLoginAttempts(0);
        userRepo.save(user);
    }
}
