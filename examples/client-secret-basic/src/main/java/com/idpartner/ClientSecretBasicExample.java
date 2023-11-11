package com.idpartner;

import java.net.URI;
import java.util.HashMap;
import java.io.File;
import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.context.request.WebRequest;

import com.idpartner.OIDCClient;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@SpringBootApplication
@Controller
public class ClientSecretBasicExample {
  private static OIDCClient idPartner;
  private static final AppConfig jsonConfig = loadConfig();;

  public static void main(String[] args) {
    if (jsonConfig == null) {
      System.out.println("Failed to load config.json");
      System.exit(1);
    }
    SpringApplication.run(ClientSecretBasicExample.class, args);

    Map<String, String> config = new HashMap<>();
    config.put("client_id", jsonConfig.getClientId());
    config.put("client_secret", jsonConfig.getClientSecret());
    config.put("redirect_uri", jsonConfig.getRedirectUri());
    config.put("account_selector_service_url", "http://localhost:9002");
    idPartner = new OIDCClient(config);
  }

  @GetMapping("/")
  public String index(Model model) {
    model.addAttribute("title", "RP Client Secret Example");
    model.addAttribute("clientId", jsonConfig.getClientId());
    return "index";
  }

  @GetMapping("/jwks")
  public ResponseEntity<String> getJWKS() {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);

    return new ResponseEntity<>(idPartner.publicJwks(), headers, HttpStatus.OK);
  }

  @GetMapping("/button/oauth")
  public ResponseEntity<Object> initiateOAuth(HttpSession session, WebRequest webRequest, SessionStatus sessionStatus,
      @RequestParam(value = "iss", required = false) String iss,
      @RequestParam(value = "visitor_id", required = false) String visitorIdParam,
      @RequestParam(value = "idpartner_token", required = false) String idPartnerToken,
      @RequestParam(value = "idp_id", required = false) String identityProviderId,
      @RequestParam(value = "claims", required = false) String claimsParam) throws Exception {
    HttpHeaders headers = new HttpHeaders();
    final String SCOPE = "openid offline_access email profile birthdate address";
    try {
      session.setAttribute("iss", iss);
      Map<String, String[]> queryParams = webRequest.getParameterMap();
      Map<String, Object> proofs = idPartner.generateProofs();
      session.setAttribute("proofs", proofs);
      Map<String, Object> extraAuthorizationParams = new HashMap<>();
      URI redirectUri = idPartner.getAuthorizationUrl(queryParams, proofs, jsonConfig.getScope(),
          extraAuthorizationParams);
      headers.setLocation(redirectUri);

      return new ResponseEntity<>(headers, HttpStatus.SEE_OTHER);
    } catch (Exception e) {
      String errorJson = "{\"error\":\"" + e.getMessage() + "\"}";
      return new ResponseEntity<>(errorJson, headers, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @GetMapping("/button/oauth/callback")
  public ResponseEntity<String> oauthCallback(HttpSession session, WebRequest webRequest, HttpServletRequest request,
      @RequestParam("response") String response) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    Map<String, String[]> queryParams = webRequest.getParameterMap();
    Map<String, Object> proofs = (Map<String, Object>) session.getAttribute("proofs");
    try {
      OIDCTokens token = idPartner.token(queryParams, proofs);
      AccessToken accessToken = token.getAccessToken();
      String userInfo = idPartner.userinfo(accessToken);
      return new ResponseEntity<>(userInfo, headers, HttpStatus.OK);
    } catch (Exception e) {
      e.printStackTrace();
      // Handle exceptions
      String errorJson = "{\"error\":\"" + e.getMessage() + "\"}";
      return new ResponseEntity<>(errorJson, headers, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private static AppConfig loadConfig() {
    try {
      ObjectMapper mapper = new ObjectMapper();
      return mapper.readValue(new File("config.json"), AppConfig.class);
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }
}
