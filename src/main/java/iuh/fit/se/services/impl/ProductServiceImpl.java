package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.product.ProductRequestDTO;
import iuh.fit.se.dtos.product.ProductResponseDTO;
import iuh.fit.se.dtos.product.ProductDetailDTO;
import iuh.fit.se.entities.product.Product;
import iuh.fit.se.entities.category.Category;
import iuh.fit.se.entities.product.ProductGroup;
import iuh.fit.se.exceptions.NotFoundException;
import iuh.fit.se.mappers.ProductMapper;
import iuh.fit.se.repositories.CategoryRepository;
import iuh.fit.se.repositories.ProductRepository;
import iuh.fit.se.services.CloudinaryService;
import iuh.fit.se.services.ProductService;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;
    private final CategoryRepository categoryRepository;
    private final ProductMapper productMapper;

    private final CloudinaryService cloudinaryService;

    public ProductServiceImpl(ProductRepository productRepository, CategoryRepository categoryRepository, ProductMapper productMapper, CloudinaryService cloudinaryService) {
        this.productRepository = productRepository;
        this.categoryRepository = categoryRepository;
        this.productMapper = productMapper;
        this.cloudinaryService = cloudinaryService;
    }

    //Get Products By Group
    @Override
    public List<ProductResponseDTO> getProductsByGroup(String productGroup) {
        ProductGroup groupEnum;
        try {
            // Convert String ("FLASH_SALE") -> Enum (ProductGroup.FLASH_SALE)
            groupEnum = ProductGroup.valueOf(productGroup.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new NotFoundException("Invalid product group: " + productGroup);
        }

        List<Product> products = productRepository.findByProductGroupAndActiveTrue(groupEnum);
        if (products.isEmpty()) {
            throw new NotFoundException("No products found for group: " + groupEnum);
        }

        return products.stream()
                .map(productMapper::toResponseDTO)
                .collect(Collectors.toList());
    }


    //Get products by category
    @Override
    public List<ProductResponseDTO> getProductsByCategory(Long categoryId) {
        List<Product> products = productRepository.findByCategory_IdCategoryAndActiveTrue(categoryId);
        if (products.isEmpty()) {
            throw new NotFoundException("No products found for category ID: " + categoryId);
        }
        return products.stream()
                .map(productMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    //Get product detail
    @Override
    public ProductDetailDTO getProductDetail(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + id));
        return productMapper.toDetailDTO(product);
    }

    //Get All
    @Override
    public List<ProductResponseDTO> getAllProducts() {

        List<Product> products = productRepository.findByActiveTrue();

        if (products.isEmpty()) {
            throw new NotFoundException("No products found");
        }
        return products.stream()
                .map(productMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

    private void calculateAndSetPrice(Product product) {
        if (product.getOldPrice() != null && product.getDiscountPercent() != null) {
            double discountFactor = (100.0 - product.getDiscountPercent()) / 100.0;
            double finalPrice = product.getOldPrice() * discountFactor;

            product.setPrice(finalPrice);
        }

        else if (product.getPrice() == null && product.getOldPrice() != null) {
            product.setPrice(product.getOldPrice());
        }
    }

    private void processThumbnails(ProductRequestDTO dto, List<MultipartFile> thumbnailFiles) throws IOException {
        List<String> finalThumbnails = new ArrayList<>();

        if (dto.getThumbnails() != null) {
            finalThumbnails.addAll(dto.getThumbnails());
        }

        if (thumbnailFiles != null && !thumbnailFiles.isEmpty()) {
            for (MultipartFile file : thumbnailFiles) {
                if (!file.isEmpty()) {
                    String url = cloudinaryService.uploadImage(file);
                    finalThumbnails.add(url);
                }
            }
            dto.setThumbnails(finalThumbnails);
        }
    }

    //Create product
    @Transactional
    @Override
    public ProductResponseDTO createProduct(ProductRequestDTO dto, MultipartFile imageFile, List<MultipartFile> thumbnailFiles) throws IOException {
        Category category = categoryRepository.findById(dto.getIdCategory())
                .orElseThrow(() -> new NotFoundException("Category not found with ID: " + dto.getIdCategory()));

        if (imageFile != null && !imageFile.isEmpty()) {

            String imageUrl = cloudinaryService.uploadImage(imageFile);

            dto.setImageProduct(imageUrl);
        } else {

            throw new RuntimeException("Image file is required for new product!");
        }

        processThumbnails(dto, thumbnailFiles);

        Product product = productMapper.toEntity(dto);
        product.setCategory(category);
        product.setThumbnails(dto.getThumbnails());

        calculateAndSetPrice(product);

        productRepository.save(product);
        return productMapper.toResponseDTO(product);
    }

    //UPDATE PRODUCT
    @Transactional
    @Override
    public ProductResponseDTO updateProduct(Long id, ProductRequestDTO dto, MultipartFile imageFile, List<MultipartFile> thumbnailFiles) throws IOException {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + id));

        if (imageFile != null && !imageFile.isEmpty()) {
            String imageUrl = cloudinaryService.uploadImage(imageFile);
            product.setImageProduct(imageUrl);
        } else if (dto.getImageProduct() != null) {
            product.setImageProduct(dto.getImageProduct());
        }

        List<String> newUploadedUrls = new ArrayList<>();
        if (thumbnailFiles != null && !thumbnailFiles.isEmpty()) {
            for (MultipartFile file : thumbnailFiles) {
                if (!file.isEmpty()) {
                    String url = cloudinaryService.uploadImage(file);
                    newUploadedUrls.add(url);
                }
            }
        }

        boolean hasUpdate = (dto.getThumbnails() != null) || (!newUploadedUrls.isEmpty());

        if (hasUpdate) {
            List<String> finalThumbnails = new ArrayList<>();

            if (dto.getThumbnails() != null) {
                finalThumbnails.addAll(dto.getThumbnails());
            }

            finalThumbnails.addAll(newUploadedUrls);

            product.setThumbnails(finalThumbnails);
        }

        if (dto.getNameProduct() != null) product.setNameProduct(dto.getNameProduct());
        if (dto.getBrand() != null) product.setBrand(dto.getBrand());
        if (dto.getOldPrice() != null) product.setOldPrice(dto.getOldPrice());
        if (dto.getDiscountPercent() != null) product.setDiscountPercent(dto.getDiscountPercent());

        if (dto.getPrice() != null) product.setPrice(dto.getPrice());

        if (dto.getStockQuantity() != null) product.setStockQuantity(dto.getStockQuantity());
        if (dto.getDescription() != null) product.setDescription(dto.getDescription());
        if (dto.getInformation() != null) product.setInformation(dto.getInformation());

        if (dto.getProductGroup() != null)
            product.setProductGroup(Enum.valueOf(ProductGroup.class, dto.getProductGroup()));

        if (dto.getIdCategory() != null) {
            Category category = categoryRepository.findById(dto.getIdCategory())
                    .orElseThrow(() -> new NotFoundException("Category not found with ID: " + dto.getIdCategory()));
            product.setCategory(category);
        }

        calculateAndSetPrice(product);

        Product updated = productRepository.save(product);
        return productMapper.toResponseDTO(updated);
    }

    //Delete product
    @Transactional
    @Override
    public void deleteProduct(Long id) {
//        Product product = productRepository.findById(id)
//                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + id));
//        productRepository.delete(product);

        Product product = productRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + id));


        product.setActive(false);

        productRepository.save(product);

        System.out.println("Đã xóa mềm sản phẩm ID: " + id);
    }

    @Override
    public List<ProductResponseDTO> filterProducts(String brand, Double minPrice, Double maxPrice, Long categoryId, String sort) {

        Sort sortOption = Sort.unsorted();

        if (sort != null) {
            switch (sort.toLowerCase()) {
                case "price_low_to_high":
                    sortOption = Sort.by(Sort.Direction.ASC, "price");
                    break;
                case "price_high_to_low":
                    sortOption = Sort.by(Sort.Direction.DESC, "price");
                    break;
                default:
                    break;
            }
        }

        List<Product> products = productRepository.filterProducts(brand, minPrice, maxPrice, categoryId, sortOption);

        if (products.isEmpty()) {

            throw new NotFoundException("No products found with given filters");
        }

        return products.stream()
                .map(productMapper::toResponseDTO)
                .collect(Collectors.toList());
    }


    @Override
    public List<ProductResponseDTO> searchProducts(String keyword) {

        if (keyword == null || keyword.trim().isEmpty()) {
            return List.of();
        }

        List<Product> products = productRepository.findByNameProductContainingIgnoreCase(keyword.trim());

        return products.stream()
                .map(productMapper::toResponseDTO)
                .collect(Collectors.toList());
    }

}
