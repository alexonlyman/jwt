package alexgr.jwt.user_service;

import alexgr.jwt.repo.UserRepo;
import alexgr.jwt.user.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepo.findUserEntityByUsername(username);
        if (user == null) {
            System.out.println("user not found" + username);
        }
        assert user != null;
        return new User(user.getUsername(), user.getPassword(), user.getAuthorities());
    }

    public List<UserEntity> getAll() {
        return userRepo.findAll();
    }

    public UserEntity update(Integer id, UserEntity user) {
        UserEntity userEntity = userRepo.findById(id).orElseThrow();
        userEntity.setPassword(user.getPassword());
        userEntity.setUsername(user.getUsername());
        userEntity.setEmail(user.getEmail());
        return userRepo.save(userEntity);
    }

    public UserEntity findUserById(Integer id) {
        return userRepo.findById(id).orElseThrow();
    }

    public void unlockAccount(UserEntity user) {
        user.setAccountNonLocked(true);
        user.setFailedLoginAttempts(0);
        userRepo.save(user);
    }

}
