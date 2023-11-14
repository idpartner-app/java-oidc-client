package com.idpartner;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest;
import com.nimbusds.oauth2.sdk.PushedAuthorizationResponse;
import com.nimbusds.oauth2.sdk.PushedAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * The OIDCClient class handles the interaction with an OpenID Connect provider.
 * It includes functionalities for generating authorization URLs, handling
 * tokens, and retrieving user information.
 */
public class OIDCClient {
  private static final String[] SUPPORTED_AUTH_METHODS = {
      "client_secret_basic",
      "tls_client_auth",
      "private_key_jwt"
  };
  private static final String SIGNING_ALG = "PS256";
  private static final String ENCRYPTION_ALG = "RSA-OAEP";
  private static final String ENCRYPTION_ENC = "A256CBC-HS512";

  private Map<String, Object> config;

  /**
   * Constructs an OIDCClient with the specified configuration.
   *
   * @param config A map containing configuration parameters such as client ID,
   *               client secret, etc.
   * @throws IllegalArgumentException If the provided configuration is null or
   *                                  invalid.
   */
  public OIDCClient(Map<String, String> config) {
    if (config == null || config.isEmpty()) {
      throw new IllegalArgumentException("Config is missing");
    }

    Map<String, String> defaultConfig = new HashMap<>();
    defaultConfig.put("account_selector_service_url", "https://auth-api.idpartner.com/oidc-proxy");
    defaultConfig.put("token_endpoint_auth_method", "client_secret_basic");
    defaultConfig.put("jwks", null);
    defaultConfig.put("client_secret", null);

    this.config = new HashMap<>(defaultConfig);
    this.config.putAll(config);

    if (!Arrays.asList(SUPPORTED_AUTH_METHODS).contains(this.config.get("token_endpoint_auth_method"))) {
      throw new IllegalArgumentException(
          "Unsupported token_endpoint_auth_method '" + config.get("token_endpoint_auth_method") +
              "'. It must be one of (" + String.join(", ", SUPPORTED_AUTH_METHODS) + ")");
    }

    Map<String, String> clientSecretConfig = new HashMap<>();
    if ("client_secret_basic".equals(this.config.get("token_endpoint_auth_method"))) {
      clientSecretConfig.put("client_secret", this.config.get("client_secret").toString());
    }

    Map<String, String> jwksConfig = new HashMap<>();
    if (this.config.get("jwks") != null) {
      JWKSet jwkSet;
      try {
        jwkSet = JWKSet.parse((String) this.config.get("jwks"));
      } catch (ParseException e) {
        throw new Error("jwks is an invalid JSON Web Key Set.");
      }
      this.config.put("jwkSet", jwkSet);
      jwksConfig.put("authorization_encrypted_response_alg", ENCRYPTION_ALG);
      jwksConfig.put("authorization_encrypted_response_enc", ENCRYPTION_ENC);
      jwksConfig.put("id_token_encrypted_response_alg", ENCRYPTION_ALG);
      jwksConfig.put("id_token_encrypted_response_enc", ENCRYPTION_ENC);
      jwksConfig.put("request_object_signing_alg", SIGNING_ALG);
    }

    this.config.put("authorization_signed_response_alg", SIGNING_ALG);
    this.config.put("id_token_signed_response_alg", SIGNING_ALG);
    this.config.putAll(clientSecretConfig);
    this.config.putAll(jwksConfig);
  }

  /**
   * Generates proofs needed for the OIDC flow such as state, nonce, and code
   * verifier.
   *
   * @return A map containing generated proofs (state, nonce, codeVerifier).
   */
  public Map<String, Object> generateProofs() {
    Map<String, Object> proofs = new HashMap<>();

    proofs.put("state", new State());
    proofs.put("nonce", new Nonce());
    proofs.put("codeVerifier", new CodeVerifier());

    return proofs;
  }

  /**
   * Constructs the authorization URL based on provided parameters.
   *
   * @param query Query parameters for the authorization request.
   * @param proofs Proofs such as state and nonce.
   * @param scope Requested OIDC scopes.
   * @param extraAuthorizationParams Additional parameters for the authorization request.
   * @return The constructed authorization URI.
   * @throws Exception If there is an error constructing the URI.
   */
  public URI getAuthorizationUrl(Map<String, String[]> query, Map<String, Object> proofs, String scope,
      Map<String, Object> extraAuthorizationParams) throws Exception {
    if (query == null)
      throw new IllegalArgumentException("The URL query parameter is required.");
    if (scope == null || scope.isEmpty())
      throw new IllegalArgumentException("The scope parameter is required.");
    if (proofs == null)
      throw new IllegalArgumentException("The proofs parameter is required.");

    if (query.get("iss") == null) {
      String accountSelectorServiceUrl = config.get("account_selector_service_url").toString();
      String clientId = config.get("client_id").toString();
      String visitorId = getFirstElementSafely(query.get("visitor_id"));
      String claims = extractClaims((Map<String, Object>) extraAuthorizationParams.get("claims"));
      String encodedScope = URLEncoder.encode(scope, StandardCharsets.UTF_8.toString());

      return new URI(accountSelectorServiceUrl + "/auth/select-accounts?client_id=" + clientId +
          "&visitor_id=" + visitorId + "&scope=" + encodedScope + "&claims=" + claims);
    }
    String iss = getFirstElementSafely(query.get("iss"));
    this.config.put("iss", iss);

    Issuer issuer = new Issuer(iss);
    OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.resolve(issuer);
    this.config.put("providerMetadata", providerMetadata);

    AuthenticationRequest authenticationRequest = null;

    authenticationRequest = new AuthenticationRequest.Builder(
        ResponseType.CODE,
        new Scope(scope.split(" ")),
        new ClientID(config.get("client_id").toString()),
        new URI(this.config.get("redirect_uri").toString()))
        .state((State) proofs.get("state"))
        .nonce((Nonce) proofs.get("nonce"))
        .responseMode(ResponseMode.JWT)
        .codeChallenge((CodeVerifier) proofs.get("codeVerifier"), CodeChallengeMethod.S256)
        .customParameter("x-fapi-interaction-id", UUID.randomUUID().toString())
        .customParameter("identity_provider_id", getFirstElementSafely(query.get("idp_id")))
        .customParameter("idpartner_token", getFirstElementSafely(query.get("idpartner_token")))
        .build();

    Map<String, Object> claims = (Map<String, Object>) extraAuthorizationParams.get("claims");
    if (claims != null) {
      ObjectMapper objectMapper = new ObjectMapper();
      String jsonClaims = objectMapper.writeValueAsString(claims);
      authenticationRequest = new AuthenticationRequest.Builder(authenticationRequest)
          .customParameter("claims", jsonClaims)
          .build();
    }
    URI requestUri = sendPushedAuthorizationRequest(authenticationRequest, providerMetadata);
    URI authorizationEndpoint = providerMetadata.getAuthorizationEndpointURI();
    return new URI(authorizationEndpoint + "?request_uri=" + requestUri.toString());
  }

  /**
   * Retrieves the public JSON Web Key Set (JWKS).
   *
   * @return A JSON string representation of the public JWKS.
   */
  public String publicJwks() {
    if (this.config.get("jwkSet") == null) {
      return "{}";
    }
    return ((JWKSet) this.config.get("jwkSet")).toString(true);
  }

  /**
   * Handles the token exchange process in the OIDC flow.
   *
   * @param query  Query parameters from the OIDC provider response.
   * @param proofs Proofs such as the code verifier.
   * @return The OIDC tokens obtained from the token endpoint.
   * @throws Exception If there is an error processing the token request.
   */
  public OIDCTokens token(Map<String, String[]> query, Map<String, Object> proofs) throws Exception {
    OIDCProviderMetadata providerMetadata = (OIDCProviderMetadata) this.config.get("providerMetadata");
    JWTClaimsSet decodedJwt = decodeJwt(getFirstElementSafely(query.get("response")), providerMetadata);
    String code = decodedJwt.getStringClaim("code");
    URI tokenEndpoint = providerMetadata.getTokenEndpointURI();

    TokenRequest tokenRequest = new TokenRequest(
        tokenEndpoint,
        new ClientSecretBasic(new ClientID(this.config.get("client_id").toString()),
            new Secret(this.config.get("client_secret").toString())),
        new AuthorizationCodeGrant(
            new AuthorizationCode(code),
            new URI(this.config.get("redirect_uri").toString()),
            (CodeVerifier) proofs.get("codeVerifier")));

    HTTPResponse tokenResponse = tokenRequest.toHTTPRequest().send();

    TokenResponse parsedResponse = OIDCTokenResponseParser.parse(tokenResponse);
    if (!parsedResponse.indicatesSuccess()) {
      throw new Error("Token request failed: " + tokenResponse.getBody());
    }
    OIDCTokenResponse tokenSuccessResponse = (OIDCTokenResponse) parsedResponse.toSuccessResponse();

    return tokenSuccessResponse.getOIDCTokens();
  }

  /**
   * Retrieves user information from the OIDC provider.
   *
   * @param accessToken The access token to authenticate the request.
   * @return A JSON string with the user information.
   * @throws Exception If there is an error during the request.
   */
  public String userinfo(AccessToken accessToken) throws Exception {
    OIDCProviderMetadata providerMetadata = (OIDCProviderMetadata) this.config.get("providerMetadata");
    URI userInfoEndpoint = providerMetadata.getUserInfoEndpointURI();
    UserInfoRequest userInfoRequest = new UserInfoRequest(
        userInfoEndpoint,
        (BearerAccessToken) accessToken);
    HTTPResponse userInfoResponse = userInfoRequest.toHTTPRequest().send();
    UserInfoResponse userInfoResponseParsed = UserInfoResponse.parse(userInfoResponse);
    if (!userInfoResponseParsed.indicatesSuccess()) {
      throw new Error("Userinfo request failed: " + userInfoResponse.getBody());
    }
    UserInfoSuccessResponse successResponse = (UserInfoSuccessResponse) userInfoResponseParsed.toSuccessResponse();

    return successResponse.getUserInfo().toJSONObject().toJSONString();
  }

  private AuthorizationRequest createRequestObject(AuthenticationRequest authenticationRequest,
      OIDCProviderMetadata providerMetadata)
      throws JOSEException {
    JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(authenticationRequest.toJWTClaimsSet())
        .issuer(this.config.get("client_id").toString())
        .audience(providerMetadata.getIssuer().toString())
        .expirationTime(Date.from(Instant.now().plusSeconds(60)))
        .issueTime(new Date())
        .notBeforeTime(new Date())
        .build();

    List<JWK> matchingKeys = ((JWKSet) this.config.get("jwkSet"))
        .filter(new JWKMatcher.Builder().keyUse(KeyUse.SIGNATURE).build()).getKeys();
    RSAKey signingKey = matchingKeys.get(0).toRSAKey();
    JWSSigner signer = new RSASSASigner(signingKey);

    SignedJWT signedJWT = new SignedJWT(
        new JWSHeader.Builder(JWSAlgorithm.PS256).keyID(signingKey.getKeyID()).build(),
        jwtClaimsSet);

    signedJWT.sign(signer);

    return new AuthorizationRequest.Builder(signedJWT, new ClientID(this.config.get("client_id").toString())).build();
  }

  private URI sendPushedAuthorizationRequest(AuthenticationRequest authenticationRequest,
      OIDCProviderMetadata providerMetadata) throws Exception {
    AuthorizationRequest requestObject = null;
    if (((JWKSet) this.config.get("jwkSet")) != null) {
      requestObject = createRequestObject(authenticationRequest, providerMetadata);
    }

    ClientSecretBasic clientSecretBasic = new ClientSecretBasic(
        new ClientID(this.config.get("client_id").toString()),
        new Secret(this.config.get("client_secret").toString()));
    PushedAuthorizationRequest parRequest = requestObject != null ? new PushedAuthorizationRequest(
        providerMetadata.getPushedAuthorizationRequestEndpointURI(),
        clientSecretBasic,
        requestObject)
        : new PushedAuthorizationRequest(
            providerMetadata.getPushedAuthorizationRequestEndpointURI(),
            clientSecretBasic,
            authenticationRequest);

    HTTPResponse parHttpResponse = parRequest.toHTTPRequest().send();

    if (parHttpResponse.indicatesSuccess()) {
      PushedAuthorizationResponse parResponse = PushedAuthorizationResponse.parse(parHttpResponse);
      PushedAuthorizationSuccessResponse successResponse = (PushedAuthorizationSuccessResponse) parResponse;
      return successResponse.getRequestURI();
    } else {
      System.out.println(parHttpResponse.getBody());
      throw new Error("Failed to get successful response from PAR endpoint");
    }
  }

  private String extractClaims(Map<String, Object> claimsObject) {
    if (claimsObject == null)
      return "";

    Set<String> claimsSet = new HashSet<>();
    Map<String, Object> userinfo = (Map<String, Object>) claimsObject.get("userinfo");
    Map<String, Object> idToken = (Map<String, Object>) claimsObject.get("id_token");

    if (userinfo != null)
      claimsSet.addAll(userinfo.keySet());
    if (idToken != null)
      claimsSet.addAll(idToken.keySet());

    return String.join("+", claimsSet);
  }

  private String getFirstElementSafely(String[] array) {
    return (array != null && array.length > 0) ? array[0] : "";
  }

  private JWTClaimsSet decodeJwt(String jwtStr, OIDCProviderMetadata providerMetadata) throws Exception {
    SignedJWT signedJWT;
    if (jwtStr.split("\\.").length == 5) {
      JWEObject jweObject = JWEObject.parse(jwtStr);

      List<JWK> matchingKeys = ((JWKSet) this.config.get("jwkSet"))
          .filter(new JWKMatcher.Builder().keyUse(KeyUse.ENCRYPTION).build()).getKeys();
      RSAKey encryptionKey = matchingKeys.get(0).toRSAKey();
      RSADecrypter decrypter = new RSADecrypter(encryptionKey);

      jweObject.decrypt(decrypter);

      signedJWT = jweObject.getPayload().toSignedJWT();
    } else {
      signedJWT = SignedJWT.parse(jwtStr);
    }

    URI jwkSetUri = providerMetadata.getJWKSetURI();
    JWKSet jwkSet = JWKSet.load(jwkSetUri.toURL());
    RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());
    RSASSAVerifier verifier = new RSASSAVerifier(rsaKey);
    if (!signedJWT.verify(verifier)) {
      throw new Error("Invalid signature");
    }
    return signedJWT.getJWTClaimsSet();
  }
}
