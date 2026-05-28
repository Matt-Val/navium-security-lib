package com.navium.security_lib.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;


/*
    Filtro de autorización que valida Tokens JWT en cada solicitud HTTP.

    Responsabilidades:
        Intercepta cada solicitud http que llega.
        Extrae el token JWT del header Authorization (Bearer) o de una Cookie HttpOnly.
        Valida que el token sea válido usando la llave secreta
        Extrae información del usuario del token (Claims)
        Configura el contexto de seguridad de Spring si el token es válido
        Bloquea el acceso si el token es inválido o ha expirado.

    Flujo de Validación:
        1. Busca el token en el header "Authorization" (Bearer <token>)
        2. Si no lo encuentra, busca el token en una Cookie llamada "token"
        3. Si existe, intenta validar el token usando la llave secreta
        4. En caso de que sea válido:
            Extrae el username del token
            Crea un objeto de autenticación de Spring Security
            Le asigna al contexto de seguridad
        5. En caso de que NO sea válido o no exista:
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
        String token = recoverToken(request);

        if (token != null) {
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
                List<GrantedAuthority> authorities = buildAuthorities(claims);

                // Si todo está bien, le da acceso a Spring Boot
                if (username != null) {
                    // Crea el token de autenticación sin credenciales
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
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

    /**
     * Recupera el token de la solicitud, buscando primero en el header Authorization
     * y luego en las cookies.
     */
    private String recoverToken(HttpServletRequest request) {
        // 1. Intentar desde el Header (Bearer)
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.replace("Bearer ", "");
        }

        // 2. Intentar desde las Cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        return null;
    }

    private List<GrantedAuthority> buildAuthorities(Claims claims) {
        Set<String> roleNames = new LinkedHashSet<>();
        addRoles(roleNames, claims.get("rol"));
        addRoles(roleNames, claims.get("roles"));

        if (roleNames.isEmpty()) {
            return Collections.emptyList();
        }

        List<GrantedAuthority> authorities = new ArrayList<>(roleNames.size());
        for (String roleName : roleNames) {
            if (roleName == null) {
                continue;
            }
            String trimmed = roleName.trim();
            if (!trimmed.isEmpty()) {
                authorities.add(new SimpleGrantedAuthority(trimmed));
            }
        }
        return authorities;
    }

    private void addRoles(Set<String> roleNames, Object claimValue) {
        if (claimValue == null) {
            return;
        }
        if (claimValue instanceof String) {
            addRoleString(roleNames, (String) claimValue);
            return;
        }
        if (claimValue instanceof Collection<?>) {
            for (Object item : (Collection<?>) claimValue) {
                if (item != null) {
                    addRoleString(roleNames, item.toString());
                }
            }
            return;
        }
        addRoleString(roleNames, claimValue.toString());
    }

    private void addRoleString(Set<String> roleNames, String value) {
        if (value == null) {
            return;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return;
        }
        if (trimmed.contains(",")) {
            for (String part : trimmed.split(",")) {
                String partTrimmed = part.trim();
                if (!partTrimmed.isEmpty()) {
                    roleNames.add(partTrimmed);
                }
            }
            return;
        }
        roleNames.add(trimmed);
    }
}