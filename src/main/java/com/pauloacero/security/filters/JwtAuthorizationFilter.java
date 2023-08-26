package com.pauloacero.security.filters;

import com.pauloacero.security.jwt.JwtUtils;
import com.pauloacero.service.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Obtener el encabezado "Authorization" de la solicitud
        String tokenHeader = request.getHeader("Authorization");

        // Verificar si el encabezado contiene un token JWT válido
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")){
            // Extraer el token de JWT (removiendo "Bearer ")
            String token = tokenHeader.substring(7);

            // Verificar si el token JWT es válido
            if (jwtUtils.isTokenValid(token)){
                // Obtener el nombre de usuario del token JWT
                String username = jwtUtils.getUsernameFromToken(token);

                // Cargar los detalles del usuario desde el servicio de detalles de usuario
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Crear un token de autenticación con el nombre de usuario y los roles del usuario
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());

                // Establecer la autenticación en el contexto de seguridad
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        // Continuar con la cadena de filtros
        filterChain.doFilter(request, response);
    }
}
