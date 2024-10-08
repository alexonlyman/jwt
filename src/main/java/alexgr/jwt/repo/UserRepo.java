package alexgr.jwt.repo;

import alexgr.jwt.user.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<UserEntity, Integer> {
    UserEntity findUserEntityByUsername(String username);

}
