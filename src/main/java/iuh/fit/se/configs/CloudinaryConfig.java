package iuh.fit.se.configs;

import com.cloudinary.Cloudinary;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class CloudinaryConfig {

    @Bean
    public Cloudinary cloudinary() {
        Map<String, String> config = new HashMap<>();
        // Cloudinary Dashboard
        config.put("cloud_name", "dunurfkzd");
        config.put("api_key", "969292357459665");
        config.put("api_secret", "0tVoKMwZ95Du7Wesc0YJsQIaoCw");

        return new Cloudinary(config);
    }
}