package pl.oremczuk.springsecurityjwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import pl.oremczuk.springsecurityjwt.models.AuthenticationRequest;
import pl.oremczuk.springsecurityjwt.models.AuthenticationResponse;
import pl.oremczuk.springsecurityjwt.util.JwtUtil;

@RestController
public class JwtController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private MyUserDetailsService myUserDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("/hello")
    public String getHelloPage() {
        return "Hello";
    }
    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest request) throws Exception {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
            ));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
            }

        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(request.getUsername());

        final String jwt = jwtUtil.generateJwtToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));

    }



}
