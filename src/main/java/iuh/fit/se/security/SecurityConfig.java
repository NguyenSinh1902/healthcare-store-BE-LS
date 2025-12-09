package iuh.fit.se.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod; // Import mới quan trọng
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter, UserDetailsService userDetailsService) {
        this.jwtFilter = jwtFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                //CẤU HÌNH CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Tắt CSRF
                .csrf(csrf -> csrf.disable())

                //Stateless Session
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //PHÂN QUYỀN
                .authorizeHttpRequests(auth -> auth
                        //PUBLIC ENDPOINTS
                        .requestMatchers("/api/auth/**", "/api/upload/**").permitAll()

                        //PUBLIC GET
                        .requestMatchers(HttpMethod.GET,
                                "/api/categories/**",
                                "/api/products/**",
                                "/api/coupons/**"
                        ).permitAll()

                        //ADMIN SPECIFIC ROUTES

                        // Dashboard
                        .requestMatchers("/api/dashboard/**").hasAuthority("ADMIN")

                        // Orders: Update Status (PUT /api/orders/{id}/status)
                        .requestMatchers(HttpMethod.PUT, "/api/orders/*/status").hasAuthority("ADMIN")

                        // Profile: Admin ban/active user (PUT /api/profile/admin/{id}/status)
                        .requestMatchers(HttpMethod.PUT, "/api/profile/admin/*/status").hasAuthority("ADMIN")

                        // Profile: Delete User
                        .requestMatchers(HttpMethod.DELETE, "/api/profile/**").hasAuthority("ADMIN")

                        //Products/Categories/Coupons (POST, PUT, DELETE)
                        .requestMatchers(HttpMethod.POST, "/api/categories/**", "/api/products/**", "/api/coupons/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/categories/**", "/api/products/**", "/api/coupons/**").hasAuthority("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/categories/**", "/api/products/**", "/api/coupons/**").hasAuthority("ADMIN")

                        //USER/AUTHENTICATED ROUTES

                        //Cart: Phải có token
                        .requestMatchers("/api/cart/**", "/api/cart-items/**").authenticated()

                        //Orders:
                        .requestMatchers("/api/orders/**").authenticated()

                        // Profile
                        .requestMatchers("/api/profile/**").authenticated()

                        // CÁC REQUEST CÒN LẠI -> Phải đăng nhập
                        .anyRequest().authenticated()
                )

                // Xử lý lỗi (Exception Handling)
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
                            res.setContentType("application/json");
                            res.getWriter().write("{\"error\": \"Unauthorized\", \"message\": \"Please log in to proceed.\"}");
                        })
                        .accessDeniedHandler((req, res, e) -> {
                            res.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403
                            res.setContentType("application/json");
                            res.getWriter().write("{\"error\": \"Forbidden\", \"message\": \"You do not have Admin rights to perform this operation\"}");
                        })
                )

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(authenticationProvider());

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}