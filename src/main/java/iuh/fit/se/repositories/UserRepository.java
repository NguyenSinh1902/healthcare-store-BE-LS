package iuh.fit.se.repositories;

import iuh.fit.se.entities.auth.Role;
import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.auth.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    //Tìm tất cả user ngoại trừ trạng thái được truyền vào
    List<User> findByStatusNot(UserStatus status);

    //Lọc theo ROLE cụ thể và loại bỏ STATUS cụ thể
    List<User> findByRoleAndStatusNot(Role role, UserStatus status);

    // Đếm user có role là USER
    long countByRole(Role role);
}