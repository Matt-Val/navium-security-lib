package com.navium.security_lib.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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

    /**
        Configura la cadena de filtros de seguridad HTTP.
        Define cuáles rutas son públicas y cuáles requieren autenticación.
        Establece el orden en que se aplican los filtros de seguridad.
        
        Configuraciones aplicadas:
            Desactiva CSRF (Cross-Site Request Forgery)
            Configura sesiones como stateless (sin estado)
            Declara rutas públicas (Swagger UI)
            Declara rutas protegidas (API de contenedores)
            Registra el filtro JWT antes del filtro estándar de Spring
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Desactivamos CSRF porque usaremos JWT
            // La protección CSRF es necesaria solo cuando usamos cookies de sesión
            // Con JWT en headers, no es vulnerable a CSRF
            .csrf(csrf -> csrf.disable())
            
            // No guardamos sesiones, cada petición debe traer su token
            // SessionCreationPolicy.STATELESS indica que no habrá HttpSession
            // Esto es necesario para APIs RESTful con autenticación JWT
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                
                // ====== RUTAS PÚBLICAS (SIN AUTENTICACIÓN) ======
                // Dejamos públicas las rutas de Swagger para ver la documentación
                // Esto permite que terceros visualicen los endpoints disponibles
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll()
                
                // ====== RUTAS PROTEGIDAS (REQUIEREN TOKEN JWT) ======
                // Se EXIGE TOKEN para cualquier petición a APIs
                // El cliente debe incluir: Authorization: Bearer <token>
                // Nota: En caso de necesitar un endpoint especifico publico: .requestMatchers(HttpMethod.GET, "/api/v0/andenes/disponibles").permitAll()
                .requestMatchers("/api/contenedores/**").authenticated()
                .requestMatchers("/api/v0/andenes/**").authenticated()
                
                // Por defecto, todas las demás rutas requieren autenticación
                // Este es un enfoque de seguridad "deny-by-default" (denegar por defecto)
                .anyRequest().authenticated()
            )

            // Registra el filtro JWT antes del filtro estándar de Spring
            // Orden de ejecución:
            //   1. JwtAuthorizationFilter valida el token JWT
            //   2. UsernamePasswordAuthenticationFilter (estándar de Spring)
            // Esto asegura que nuestro filtro se ejecute primero
            .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
