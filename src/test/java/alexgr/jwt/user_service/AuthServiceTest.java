package alexgr.jwt.user_service;

import alexgr.jwt.repo.UserRepo;
import alexgr.jwt.user.UserEntity;
import alexgr.jwt.utils.AuthenticationResponse;
import alexgr.jwt.utils.JwtTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.AuthenticationManager;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {
    @Mock
    private UserRepo userRepo;
    @Mock
    private JwtTokenService tokenService;
    @Mock
    private AuthenticationManager manager;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        authService = new AuthService(userRepo, tokenService, manager);
    }
    @Test
    void testRegister() {
        UserEntity user = new UserEntity();
        user.setEmail("test@example.com");
        user.setPassword("password");
        user.setUsername("testuser");


        when(tokenService.generateToken(any(UserEntity.class))).thenReturn("testToken");

        AuthenticationResponse response = authService.register(user);

        verify(userRepo).save(any(UserEntity.class));
        verify(tokenService).generateToken(any(UserEntity.class));
        assertEquals("testToken", response.getToken());
    }

    @Test
    void testLogin() {
        UserEntity user = new UserEntity();
        user.setUsername("testuser");

        UserEntity foundUser = new UserEntity();
        foundUser.setUsername("testuser");
        foundUser.setEmail("test@example.com");

        when(userRepo.findUserEntityByUsername("testuser")).thenReturn(foundUser);
        when(tokenService.generateToken(foundUser)).thenReturn("testToken");

        AuthenticationResponse response = authService.login(user);

        verify(userRepo).findUserEntityByUsername("testuser");
        verify(tokenService).generateToken(foundUser);
        assertEquals("testToken", response.getToken());
    }


}