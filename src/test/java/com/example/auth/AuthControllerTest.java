package com.example.auth;

import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    private static final String REGISTER = "/api/auth/register";
    private static final String LOGIN = "/api/auth/login";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void registerStoresBcryptHashInsteadOfPlainPassword() throws Exception {
        send(REGISTER, body("user@mail.com", "rahasia123"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User registered successfully"))
                .andExpect(jsonPath("$.email").value("user@mail.com"))
                .andExpect(jsonPath("$.password").doesNotExist());

        User saved = userRepository.findByEmail("user@mail.com").orElseThrow();
        assertThat(saved.getPassword()).isNotEqualTo("rahasia123").startsWith("$2a$");
        assertThat(passwordEncoder.matches("rahasia123", saved.getPassword())).isTrue();
    }

    @Test
    void registerRejectsDuplicateEmailRegardlessOfCase() throws Exception {
        send(REGISTER, body("user@mail.com", "rahasia123")).andExpect(status().isCreated());

        send(REGISTER, body("User@Mail.com", "rahasia456"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email is already registered"));

        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void registerRejectsInvalidEmail() throws Exception {
        send(REGISTER, body("not-an-email", "rahasia123"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Validation failed"))
                .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void registerRejectsBlankEmail() throws Exception {
        send(REGISTER, body("", "rahasia123"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists());
    }

    @Test
    void registerRejectsShortPassword() throws Exception {
        send(REGISTER, body("user@mail.com", "short"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void registerRejectsPasswordLongerThanBcryptLimit() throws Exception {
        send(REGISTER, body("user@mail.com", "a".repeat(73)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void registerRejectsMissingFields() throws Exception {
        send(REGISTER, "{}")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void registerRejectsMalformedJson() throws Exception {
        send(REGISTER, "{ not json")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Request body is missing or malformed"));
    }

    @Test
    void loginSucceedsWithCorrectCredentials() throws Exception {
        send(REGISTER, body("user@mail.com", "rahasia123")).andExpect(status().isCreated());

        send(LOGIN, body("User@Mail.com", "rahasia123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.email").value("user@mail.com"));
    }

    @Test
    void loginRejectsWrongPassword() throws Exception {
        send(REGISTER, body("user@mail.com", "rahasia123")).andExpect(status().isCreated());

        send(LOGIN, body("user@mail.com", "salah12345"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void loginRejectsUnknownEmailWithSameMessage() throws Exception {
        send(LOGIN, body("nobody@mail.com", "rahasia123"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void loginRejectsInvalidPayload() throws Exception {
        send(LOGIN, body("not-an-email", ""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    private ResultActions send(String url, String json) throws Exception {
        return mockMvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private String body(String email, String password) {
        return "{\"email\":\"%s\",\"password\":\"%s\"}".formatted(email, password);
    }
}
