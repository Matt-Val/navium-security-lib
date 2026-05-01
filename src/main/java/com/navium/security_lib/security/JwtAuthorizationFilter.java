package com.navium.security_lib.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;


/*
    Filtro de autorización que valida Tokens JWT en cada solicitud HTTP.

    Responsabilidades:
        Intercepta cada solicitud http que llega.
        Extrae el token JWT del header Authorization (Bearer)
        Valida que el token sea válido usando la llave secreta
        Extrae información del usuario del token (Claims)
        Configura el contexto de seguridad de Spring si el token es válido
        Bloquea el acceso si el token es inválido o ha expirado.

    Flujo de Validación:
        Busca el header de Authorization en la solicitud
        Si existe y comienza con "Bearer" y extrae ese token
        Intenta validar el token usando la llave secreta
        En caso de que sea válido:
            Extrae el username del token
            Crea un objeto de autenticación de Spring Security
            Le asigna al contexto de seguridad
        En caso de que NO sea válido:
            Limpia el contexto (bloquea el acceso)
            Continúa con la cadena de filtros
*/

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    /*
        llave secreta para validar la firma del JWT.
        Se carga desde application.properties
        Debe ser la misma que se usa para generar tokens.
    */

    @Value("${jwt.secret}")
    private String secret;

    /*
        Filtra cada solicitud HTTP para validar el token JWT.
        EL método se ejecuta una vez por solicitud.

        Request: La solicitud HTTP.
        Response: La respuesta HTTP.
        filterChain: Cadena de filtros de seguridad.
        ServletException: Si ocurre un error relacionado con servlet.
        IOException: Si ocurre un error en la entrada o salida.
    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //Obtiene el header "Authorization"
        // Formato esperado: "Bearer <Token>"
        String header = request.getHeader("Authorization");

        // Solo procesa cuando el header ya existe y comienza con "Bearer"
        if (header != null && header.startsWith("Bearer ")) {

            // Extrae el token eliminando el "Bearer"
            String token = header.replace("Bearer ", "");
            try {
                // --- VALIDACIONES DEL TOKEN ---
                // Revisa si la llave encaja con la llave secreta
                // Valida la firma usando un código de autenticación (HASH)
                Claims claims = Jwts.parserBuilder()
                        // Establece la clave en HASH para validar la firma
                        .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        // Parsea y valida el token.
                        .parseClaimsJws(token)
                        // Obtiene el cuerpo del token
                        .getBody();

                // Extrae el username del token (subject)

                String username = claims.getSubject();

                // Si todo está bien, le da acceso a Spring Boot
                if (username != null) {
                    // Crea el token de autenticación sin credenciales
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                    // Asigna la autenticación al contexto de seguridad de Spring
                    SecurityContextHolder.getContext().setAuthentication(auth);
                }
            } catch (Exception e) {
                System.out.println("ERROR DE JWT: " + e.getMessage());
                e.printStackTrace();

                // Si el token es falso o expiró, limpia el contexto (bloquea el paso)
                SecurityContextHolder.clearContext();
            }
        }
        // Continúa con la cadena de filtros (procesa la solicitud)
        filterChain.doFilter(request, response);
    }
}