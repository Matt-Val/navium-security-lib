package com.navium.security_lib.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
    Configuración de seguridad para la aplicación.
    Esta clase define las políticas de seguridad utilizando Spring Security con autenticación JWT.
    
    Flujo de autenticación:
    1. Cliente envía credenciales para obtener token JWT<
    2. En solicitudes posteriores, cliente incluye token en header Authorization
    3. JwtAuthorizationFilter valida el token antes de procesar la solicitud
    4. Si el token es válido, la solicitud es procesada normalmente 
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
        Filtro personalizado para validar tokens JWT.
        Se inyecta automáticamente por Spring y se utiliza para validar cada solicitud HTTP que llega a la aplicación.
     */
    @Autowired
    private JwtAuthorizationFilter jwtAuthorizationFilter;

    @Autowired(required = false)
    private List<Customizer<AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry>> authorizeCustomizers;

    /**
        Configura la cadena de filtros de seguridad HTTP.
        Define cuáles rutas son públicas y cuáles requieren autenticación.
        Establece el orden en que se aplican los filtros de seguridad.
        
        Configuraciones aplicadas:
            Habilita CORS (Cross-Origin Resource Sharing)
            Desactiva CSRF (Cross-Site Request Forgery)
            Configura sesiones como stateless (sin estado)
            Declara rutas públicas (Swagger UI)
            Declara rutas protegidas (API de contenedores)
            Registra el filtro JWT antes del filtro estándar de Spring

        Nota: los claims "rol"/"roles" se mapean a authorities sin prefijo ROLE_;
        en servicios consumidores usa hasAuthority("ROL_OPERADOR") u otros valores del claim.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Habilitamos CORS con configuración por defecto
            .cors(Customizer.withDefaults())
            // Desactivamos CSRF porque usaremos JWT
            .csrf(csrf -> csrf.disable())
            
            // No guardamos sesiones, cada petición debe traer su token
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {

                // ====== RUTAS PÚBLICAS (SIN AUTENTICACIÓN) ======
                auth.requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll();

                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();

                // Optional extension point: services can add role-based rules with hasAuthority.
                if (authorizeCustomizers != null) {
                    for (Customizer<AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry> customizer : authorizeCustomizers) {
                        customizer.customize(auth);
                    }
                }
                
                // ====== RUTAS PROTEGIDAS (REQUIEREN TOKEN JWT) ======
                auth.requestMatchers("/api/contenedores/**").authenticated();
                auth.requestMatchers("/api/agendamientos/**").authenticated();
                auth.requestMatchers("/api/v0/andenes/**").authenticated();

                // Por defecto, todas las demás rutas requieren autenticación
                auth.anyRequest().authenticated();
            })

            // Registra el filtro JWT antes del filtro estándar de Spring
            .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
        Configuración de CORS por defecto para permitir credenciales (Cookies HttpOnly).
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // IMPORTANTE: Permite el envío de cookies HttpOnly
        configuration.setAllowCredentials(true);
        // Lista de orígenes permitidos (ajustar según entorno)
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200", "http://localhost:5173"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setExposedHeaders(List.of("Set-Cookie"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
