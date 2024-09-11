package alexgr.jwt.user_service;

import alexgr.jwt.repo.UserRepo;
import alexgr.jwt.user.UserEntity;
import alexgr.jwt.utils.AuthenticationResponse;
import alexgr.jwt.utils.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepo userRepo;
    private final JwtTokenService tokenService;
    private final AuthenticationManager manager;

    public AuthenticationResponse register(UserEntity user) {
        UserEntity userEntity = new UserEntity();
        userEntity.setEmail(user.getEmail());
        userEntity.setPassword(user.getPassword());
        userEntity.setUsername(user.getUsername());
        userEntity.setRole(user.getRole());
        userRepo.save(userEntity);
        String token = tokenService.generateToken(userEntity);
        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }



    public AuthenticationResponse login(UserEntity user) {
        UserEntity entity = userRepo.findUserEntityByUsername(user.getUsername());
        String token = tokenService.generateToken(entity);
        return AuthenticationResponse.builder()
                .token(token)
                .build();

    }
}
