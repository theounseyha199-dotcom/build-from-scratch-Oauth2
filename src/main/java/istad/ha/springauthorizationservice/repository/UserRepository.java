package istad.ha.springauthorizationservice.repository;

import java.util.Optional;

import istad.ha.springauthorizationservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);
}
