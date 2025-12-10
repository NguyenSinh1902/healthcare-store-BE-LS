package iuh.fit.se.security;

import iuh.fit.se.repositories.UserRepository;
import iuh.fit.se.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Lay header Authorization tu request
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        // Neu khong co token thi bo qua
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            // Giai ma token de lay email nguoi dung
            String email = jwtUtil.extractUsername(token);

            // Neu email hop le va chua co thong tin xac thuc trong SecurityContext
            if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                var user = userRepository.findByEmail(email).orElse(null);

                if (user != null) {
                    // Tao doi tuong authentication tu user
                    var authToken = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Dat authentication vao context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // Neu token loi thi bo qua va khong chan request
        }

        filterChain.doFilter(request, response);
    }
}
