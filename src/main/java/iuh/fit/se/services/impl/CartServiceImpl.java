package iuh.fit.se.services.impl;

import iuh.fit.se.dtos.cart.CartResponseDTO;
import iuh.fit.se.dtos.cartitem.CartItemRequestDTO;
import iuh.fit.se.dtos.cartitem.CartItemResponseDTO;
import iuh.fit.se.entities.auth.User;
import iuh.fit.se.entities.cart.Cart;
import iuh.fit.se.entities.cartitem.CartItem;
import iuh.fit.se.entities.product.Product;
import iuh.fit.se.exceptions.NotFoundException;
import iuh.fit.se.mappers.CartItemMapper;
import iuh.fit.se.mappers.CartMapper;
import iuh.fit.se.repositories.CartItemRepository;
import iuh.fit.se.repositories.CartRepository;
import iuh.fit.se.repositories.ProductRepository;
import iuh.fit.se.repositories.UserRepository;
import iuh.fit.se.services.CartService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class CartServiceImpl implements CartService {

    private final CartRepository cartRepository;
    private final CartItemRepository cartItemRepository;
    private final ProductRepository productRepository;
    private final UserRepository userRepository;
    private final CartMapper cartMapper;
    private final CartItemMapper cartItemMapper;

    public CartServiceImpl(CartRepository cartRepository, CartItemRepository cartItemRepository,
                           ProductRepository productRepository, UserRepository userRepository,
                           CartMapper cartMapper, CartItemMapper cartItemMapper) {
        this.cartRepository = cartRepository;
        this.cartItemRepository = cartItemRepository;
        this.productRepository = productRepository;
        this.userRepository = userRepository;
        this.cartMapper = cartMapper;
        this.cartItemMapper = cartItemMapper;
    }

    //Tự động lấy hoặc tạo giỏ hàng
    private Cart getOrCreateCartByUserId(Long userId) {
        return cartRepository.findByUser_IdUser(userId)
                .orElseGet(() -> {
                    User user = userRepository.findById(userId)
                            .orElseThrow(() -> new NotFoundException("User not found ID: " + userId));
                    Cart newCart = new Cart();
                    newCart.setUser(user);
                    newCart.setTotalAmount(0.0);
                    return cartRepository.save(newCart);
                });
    }

    //Tính lại tổng tiền
    private void updateCartTotal(Cart cart) {
        List<CartItem> items = cartItemRepository.findByCart_IdCart(cart.getIdCart());
        double total = items.stream().mapToDouble(CartItem::getTotalPrice).sum();
        cart.setTotalAmount(total);
        cartRepository.save(cart);
    }

    @Override
    public CartResponseDTO getCartByUser(Long userId) {
        Cart cart = getOrCreateCartByUserId(userId);
        return cartMapper.toResponseDTO(cart);
    }

    @Override
    @Transactional
    public CartItemResponseDTO addItemToCart(Long userId, CartItemRequestDTO requestDTO) {
        Cart cart = getOrCreateCartByUserId(userId);

        Product product = productRepository.findById(requestDTO.getIdProduct())
                .orElseThrow(() -> new NotFoundException("Product not found with ID: " + requestDTO.getIdProduct()));

        CartItem existingItem = cartItemRepository.findByCart_IdCartAndProduct_IdProduct(cart.getIdCart(), product.getIdProduct())
                .orElse(null);

        CartItem cartItem;
        if (existingItem != null) {
            existingItem.setQuantity(existingItem.getQuantity() + requestDTO.getQuantity());
            existingItem.setTotalPrice(existingItem.getQuantity() * product.getPrice());
            cartItem = cartItemRepository.save(existingItem);
        } else {
            cartItem = new CartItem();
            cartItem.setCart(cart);
            cartItem.setProduct(product);
            cartItem.setQuantity(requestDTO.getQuantity());
            cartItem.setTotalPrice(product.getPrice() * requestDTO.getQuantity());
            cartItemRepository.save(cartItem);
        }

        updateCartTotal(cart);
        return cartItemMapper.toResponseDTO(cartItem);
    }

    @Override
    @Transactional
    public CartItemResponseDTO updateItemQuantity(Long userId, Long cartItemId, Integer newQuantity) {
        CartItem item = cartItemRepository.findById(cartItemId)
                .orElseThrow(() -> new NotFoundException("Cart item not found"));

        if (!item.getCart().getUser().getIdUser().equals(userId)) {
            throw new RuntimeException("Unauthorized: You do not own this cart item");
        }

        if (newQuantity <= 0) {
            Cart cart = item.getCart();
            cartItemRepository.delete(item);
            updateCartTotal(cart);
            return null;
        } else {
            item.setQuantity(newQuantity);
            item.setTotalPrice(item.getProduct().getPrice() * newQuantity);
            CartItem savedItem = cartItemRepository.save(item);
            updateCartTotal(item.getCart());
            return cartItemMapper.toResponseDTO(savedItem);
        }
    }

    @Override
    @Transactional
    public void removeItemFromCart(Long userId, Long cartItemId) {
        CartItem item = cartItemRepository.findById(cartItemId)
                .orElseThrow(() -> new NotFoundException("Cart item not found"));

        if (!item.getCart().getUser().getIdUser().equals(userId)) {
            throw new RuntimeException("Unauthorized: You do not own this cart item");
        }

        Cart cart = item.getCart();
        cartItemRepository.delete(item);
        updateCartTotal(cart);
    }

    @Override
    @Transactional
    public void clearCartByUser(Long userId) {
        Cart cart = cartRepository.findByUser_IdUser(userId)
                .orElseThrow(() -> new NotFoundException("Cart not found"));

        // Chỉ xóa item thuộc cart của user này
        cartItemRepository.deleteAllByCart_IdCart(cart.getIdCart());

        cart.setTotalAmount(0.0);
        cartRepository.save(cart);
    }
}