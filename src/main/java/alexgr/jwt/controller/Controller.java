package alexgr.jwt.controller;

import alexgr.jwt.user.UserEntity;
import alexgr.jwt.user_service.AuthService;
import alexgr.jwt.utils.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class Controller {
    private final AuthService userService;
    private final Logger logger = LoggerFactory.getLogger(Controller.class);

    @PostMapping
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserEntity user) {
        return ResponseEntity.ok(userService.register(user));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody UserEntity user) {
        logger.info("login data " + user.getPassword() + user.getUsername());

        return ResponseEntity.ok(userService.login(user));
    }
}
