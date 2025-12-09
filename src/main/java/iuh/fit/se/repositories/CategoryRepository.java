package iuh.fit.se.repositories;

import iuh.fit.se.entities.category.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {

    //Get all parent categories (parentCategoryId = null)
    List<Category> findByParentCategoryIdIsNull();

    //Get all sub categories
    List<Category> findByParentCategoryId(Long parentId);

    //Search categories by name
    Optional<Category> findByNameCategory(String nameCategory);
}
