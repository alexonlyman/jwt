package alexgr.jwt.user_service;

import alexgr.jwt.repo.UserRepo;
import alexgr.jwt.user.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

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
}
