package alexgr.jwt.controller;

import alexgr.jwt.user.UserEntity;
import alexgr.jwt.user_service.AuthService;
import alexgr.jwt.user_service.UserService;
import alexgr.jwt.utils.AuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.AccountLockedException;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class Controller {
    private final AuthService userService;
    private final UserService service;
    private final Logger logger = LoggerFactory.getLogger(Controller.class);

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserEntity user) {
        return ResponseEntity.ok(userService.register(user));
    }

    @GetMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody UserEntity user) throws AccountLockedException {
        logger.info("login data " + user.getPassword() + " " + user.getUsername());

        return ResponseEntity.ok(userService.login(user));
    }

    @GetMapping("/get")
    @PreAuthorize("hasRole('MODERATOR')")
    public ResponseEntity<List<UserEntity>> getAll() {
        return ResponseEntity.ok(service.getAll());
    }

    @PatchMapping("/update/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<UserEntity> updateUser(@PathVariable Integer id, @RequestBody UserEntity user) {
        return ResponseEntity.ok(service.update(id, user));
    }

    @PutMapping("/unblock/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<Void> unblockAcc(@PathVariable Integer id) {
        UserEntity user = service.findUserById(id);
        service.unlockAccount(user);
        return ResponseEntity.ok().build();
    }

}
