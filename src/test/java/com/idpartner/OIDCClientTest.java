package com.idpartner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.github.tomakehurst.wiremock.WireMockServer;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.github.tomakehurst.wiremock.client.WireMock.*;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class OIDCClientTest {
  @Nested
  class Config {
    @Test
    void testConstructorThrowsAnErrorIfConfigIsNotProvided() {
      IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
        new OIDCClient(null);
      });
      assertEquals("Config is missing", exception.getMessage());
    }

    @Test
    void testConstructorThrowsAnErrorIfAuthMethodIsNotSupported() {
      IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
        Map<String, String> config = new HashMap<>();
        config.put("token_endpoint_auth_method", "unsupported");
        new OIDCClient(config);
      });

      assertTrue(exception.getMessage().contains("Unsupported token_endpoint_auth_method 'unsupported'"));
    }
  }

  @Nested
  class PublicJWKS {
    @Test
    void testReturnsEmptyJsonIfJwksConfigIsNotProvided() {
      Map<String, String> config = new HashMap<>();
      config.put("client_id", "test-client-id");
      config.put("client_secret", "test-client-secret");
      OIDCClient oidcClient = new OIDCClient(config);
      String publicJwks = oidcClient.publicJwks();

      assertEquals("{}", publicJwks);
    }

    @Test
    void testReturnsAValidJsonWhenJwksConfigIsProvided() {
      Map<String, String> config = new HashMap<>();
      config.put("client_id", "test-client-id");
      config.put("client_secret", "test-client-secret");
      config.put("jwks",
          "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test-key-id\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"test-n\",\"e\":\"AQAB\", \"d\":\"test-d\"}]}");
      OIDCClient oidcClient = new OIDCClient(config);

      String publicJwks = oidcClient.publicJwks();

      assertNotNull(publicJwks);
      assertTrue(publicJwks.contains("\"kty\":\"RSA\""));
      assertFalse(publicJwks.contains("\"d\""));
    }
  }

  @Nested
  class GenerateProofs {
    @Test
    void testGenerateProofs() {
      Map<String, String> config = new HashMap<>();
      config.put("client_id", "test-client-id");
      config.put("client_secret", "test-client-secret");
      OIDCClient oidcClient = new OIDCClient(config);

      Map<String, Object> proofs = oidcClient.generateProofs();

      assertTrue(((State) proofs.get("state")).getValue().length() >= 43);
      assertTrue(((Nonce) proofs.get("nonce")).getValue().length() >= 43);
      assertTrue(((CodeVerifier) proofs.get("codeVerifier")).getValue().length() >= 43);
    }
  }

  @Test
  void testGetAuthorizationUrlRedirectsToAccountSelection() throws Exception {
    Map<String, String> config = new HashMap<>();
    config.put("client_id", "test-client-id");
    config.put("client_secret", "test-client-secret");
    config.put("redirect_uri", "https://example.com/callback");

    OIDCClient oidcClient = new OIDCClient(config);

    Map<String, Object> proofs = oidcClient.generateProofs();
    String scope = "openid email";

    URI authorizationUrl = oidcClient.getAuthorizationUrl(new HashMap<>(), proofs, scope, new HashMap<>());

    assertNotNull(authorizationUrl);
    System.out.println(authorizationUrl.toString());
    assertTrue(authorizationUrl.toString().equals(
        "https://auth-api.idpartner.com/oidc-proxy/auth/select-accounts?client_id=test-client-id&visitor_id=&scope=openid+email&claims="));
  }

  @Nested
  class GettingUserInfo {
    private WireMockServer wireMockServer;

    @BeforeEach
    public void setup() {
      wireMockServer = new WireMockServer(options().port(9001));
      wireMockServer.start();
      configureFor("localhost", 9001);
    }

    @AfterEach
    public void teardown() {
      wireMockServer.stop();
    }

    @Test
    void testItGetsTheUserInfo() throws Exception {
      // mock OIDC requests (discovery, par)
      stubFor(get(urlEqualTo("/oidc/.well-known/openid-configuration"))
          .willReturn(aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody(
                  "{\"acr_values_supported\":[\"urn:mace:incommon:iap:silver\"],\"authorization_endpoint\":\"http://localhost:9001/oidc/auth\",\"claims_parameter_supported\":true,\"claims_supported\":[\"sub\",\"vc.MockBankCredential\",\"payment_details\",\"payment_processing\",\"address\",\"email\",\"birthdate\",\"family_name\",\"given_name\",\"age_over_18\",\"age_over_21\",\"age_over_25\",\"acr\",\"sid\",\"auth_time\",\"iss\"],\"code_challenge_methods_supported\":[\"S256\"],\"end_session_endpoint\":\"http://localhost:9001/oidc/session/end\",\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"],\"issuer\":\"http://localhost:9001/oidc\",\"jwks_uri\":\"http://localhost:9001/oidc/jwks\",\"registration_endpoint\":\"http://localhost:9001/oidc/reg\",\"authorization_response_iss_parameter_supported\":true,\"response_modes_supported\":[\"form_post\",\"fragment\",\"query\",\"jwt\",\"query.jwt\",\"fragment.jwt\",\"form_post.jwt\"],\"response_types_supported\":[\"code\"],\"scopes_supported\":[\"openid\",\"offline_access\",\"vc.MockBankCredential\",\"payment_details\",\"payment_processing\",\"address\",\"email\",\"profile\",\"age_over_18\",\"age_over_21\",\"age_over_25\"],\"subject_types_supported\":[\"public\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"tls_client_auth\",\"private_key_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"PS256\"],\"token_endpoint\":\"http://localhost:9001/oidc/token\",\"id_token_signing_alg_values_supported\":[\"PS256\"],\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\"],\"id_token_encryption_enc_values_supported\":[\"A256CBC-HS512\"],\"pushed_authorization_request_endpoint\":\"http://localhost:9001/oidc/request\",\"request_parameter_supported\":true,\"request_uri_parameter_supported\":false,\"request_object_signing_alg_values_supported\":[\"PS256\"],\"request_object_encryption_alg_values_supported\":[\"A128KW\",\"A256KW\",\"dir\",\"RSA-OAEP\"],\"request_object_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A128GCM\",\"A256CBC-HS512\",\"A256GCM\"],\"userinfo_endpoint\":\"http://localhost:9001/oidc/me\",\"payment_details_info_endpoint\":\"http://localhost:9001/oidc/payment_details\",\"payment_processing_endpoint\":\"http://localhost:9001/oidc/payment_processing\",\"authorization_signing_alg_values_supported\":[\"PS256\"],\"authorization_encryption_alg_values_supported\":[\"RSA-OAEP\"],\"authorization_encryption_enc_values_supported\":[\"A256CBC-HS512\"],\"introspection_endpoint\":\"http://localhost:9001/oidc/token/introspection\",\"revocation_endpoint\":\"http://localhost:9001/oidc/token/revocation\",\"tls_client_certificate_bound_access_tokens\":true,\"claim_types_supported\":[\"normal\"],\"mtls_endpoint_aliases\":{\"token_endpoint\":\"undefined/token\",\"introspection_endpoint\":\"undefined/token/introspection\",\"revocation_endpoint\":\"undefined/token/revocation\",\"userinfo_endpoint\":\"undefined/me\",\"pushed_authorization_request_endpoint\":\"undefined/request\",\"payment_details_info_endpoint\":\"undefined/payment_details\",\"payment_processing_endpoint\":\"undefined/payment_processing\"}}")));
      stubFor(post(urlEqualTo("/oidc/request"))
          .willReturn(aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody(
                  "{\"expires_in\":60,\"request_uri\":\"urn:ietf:params:oauth:request_uri:1duWT28BU4eM4l1cnXgVN\"}")));

      // Get authorization url
      Map<String, String> config = new HashMap<>();
      config.put("client_id", "test-client-id");
      config.put("client_secret", "test-client-secret");
      config.put("redirect_uri", "https://example.com/callback");
      config.put("jwks",
          "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"3eL_LSEgEHCNa45mwU7zZ83SEHvX2MesdKWcP14jQ8s\",\"use\":\"sig\",\"alg\":\"PS256\",\"e\":\"AQAB\",\"n\":\"0bml-h4oJEkmonIBzKZWKoaEt_jn5exY06RwOY-EB6Xp5RPbnQj8AdEW6tl8XBnpdJzhYMb7dnySzRj--jMxG_K8ZhTjLG68og4sm66H08QhWUey1lCN3vTvni8tCZtc7iPKgXJXTzyIkOse-UVkZwhQngPCh7MWjFcG4UfF97APl8XKcjpyshKakfYSpfbKoFqvRbqlJAKCyiwnVf3Ea-RXjh9spLsd77qTNMJEQt14PJxruYXTHPPubKvTJRqwR_ObxYrFxE5h8UZLFk8QYd6k_qKXdV0h2KNuu-PzmyIq7RmQMTr7M4xWexLzrQ7msnsPFJHncXfUD1-jQMtK5Q\",\"d\":\"gDpoFuM1W-o16wCVxRC2gk24-9r9voChVtWloCv1Z8-zkFJx5jPGET5MKs9Kz-0v5hK9YjSHL0y_XRM5YrTGA_aH5kpDE7mpL9RGxfESLxIt6a6C07Jw668KiscBXGxXh2rut_K3G0VBool_aJ1a4_wbfmGCIQIIeUoEdN0zV1p84ZfCTpwDbbxfnK83ia6ke_RQmoKBjrUyiciUF6jiZEfb-1Vm7aE2NWU8yhmiZ14VAq0YR3xq0OlE8FxjWpr9Lr1i-5Gy-LDOnMRM4zfvYqC_FsiOQ-wGxAxMme_-tm3B05OIsk_O82YpyxpBZYgHn7AK7xahAQMMLiL2y2viyQ\",\"p\":\"7UUoo8AKof_cIhRBSwmFhTt7_e8BZ7w0uPCAcSv4DNepCoUoTSNDHuuUmgPEULmQplHwhH-wW7ACVvylSZT4JYq-qwSVr9wJoFAYQDYiJizP73eVnFkfqiv2-xwPQaFONwGGxixuz0r8j16Tpe4iMK8Hy-LYpjucvTp6RrNHgls\",\"q\":\"4kfZ2710YTnCXUsgga-lZxxDIloJ55iLtRSRizRGyxVCNkH1IMoo6pf59AiPkyk1iWYTx4IS_SkelSPWNtJLnFKmgocYikILsiVVSOoI1vkq9la3FTmJkRNzPfTtFWVf0_e0Ff7dkQxr3XBEZUVS0o9-y_V3k7sMsnfuajjva78\",\"dp\":\"WFk_J7Izg1z1SA9IvLsf55tdsRFU8Z6H9zE-cmWP6KBJBmzMs-Rkctf_rlWmvPRL41Jxf7TYI1vnkyJiHYMF31zJYH7FigUh5HrOfOJrVtGq350krWIWQ1Q5lAk_uQ1qRVshJxuWa0OdxXjO-6MvQfd6rLWcPFHILEHhFABfqS8\",\"dq\":\"GMe3kvnfadpSb7cPe0RJ_823iGaF2Sf6fL0g5za1Xf4Y_yof9xRMgMxd4hyh5ILJyx8zoVCcVb8QC1MeXWiQQTFH7NlwlYuADmVKPq7qguhMjSeX6yoe55VStIFDCWnNob_pp9L-XqkWkux9gP2jgU2XnCxoiPQeAtlhcZ6Eka8\",\"qi\":\"Rh3yHepiLVy2gxHepFp2Yi9qSCULNCySjpDy9eeegEHQMIlH5cdO6Q5UmAtQZwoexWgXhmL8hPcgKumcGq0ZG_EpStIy176-McxtkmpbycY8Bfw6rk1FH2Sfn44oIB2JxUm8yHouh6UMz3e_WeisrmotbeAmH0NtG8DyPkTSgmA\"},{\"kty\":\"RSA\",\"kid\":\"u64VsIB-cxX3NHf1nYn1OtBXmWWQfZZp2BVN1rZL6XU\",\"use\":\"enc\",\"alg\":\"RSA-OAEP\",\"e\":\"AQAB\",\"n\":\"0CIIQ8dAvOfVE38owR4I03lu1oHmCJz0vSKCRWVyNXSfXwl00eH6JmyDC8sFo2h66iU8vNBauYELoxNf4yT9hXsEcDgJcf9NPW186LSttqqgZ8wSycS7Pn3YTfbzH45R5mH_1zvsKnI8Xwi2DibpOht0bVWStG-EXkAkj6YQdSR1cMQXvtBIetWP6cPx7kG-qzjze3mvtIucnKRnphbW31Bker2Ykur3_ySqXJpCxUx3TchL5-pckTfS9Na6VALIBTLR8dHPq1GJXVgQOCh6GrY7ljIY7ZbkJW2_n1SgyNT49SuxBrPWKiIJW2uIdgMtq3Fp-BFMqJJGaqQ_W2jtAw\",\"d\":\"x7A_ObhMNnI_jusrkM1eLneNjiUnLRBaB7S6RBam0v7HgYkzGcO0G3V07bWl_Tfa5hdABO_qe5yCK74E-4ub6ZszkO9SsJr_4nXPp_zhxiZCrBOx2v_znmtjQroyXQ5RKbbQnhKR7c-YeJ2E_mL61ZNNyzCVBqUP3NWxvljX5WqQiwsap-RN2ZiCXKrGiC_pG59uS5NSTNqf2cgXy0eSlQqt-7T6ZAZtsCz0I6pUYfHbXa3lIHCCRtTDWoVIoaKUa01FqyBeE04V6DvU9AOZWcK670cXbzhG1kkEk5HHYrQabPrBFXtRaOrApaasGDbZDv4fRW31WnNYLuhllPcQMQ\",\"p\":\"55y41df36jmE0eQmLtI1jLAq7Adw-AhweUUL-Sklf4GkzCEnJ2wVguiCni8NrFMRiCrM95ntFwT6o1neuG4St3rK5wvE_SOYbLvw2MMnjqLVr4zbbDuLJ-w8-SeqDuFRxHkR6xp8J-YwXeD5N4blceEqU36XHpChcZkzoSWCO68\",\"q\":\"5gxo1-MeuxMk_-RbS85hWMyQzVOBXGpuUlDpFELB2FxjAaaEN9bDRplWfVwTL-txN24NhFZepd8Bf7NL9nAGmGtTiEWhK5jQZz_WeXA6zRLwcm1v9Hbl516baMQy1cOa5VUyrGTsjVO3Q35j8fpRFa_RK-h3U6_bdDpO3UMyFO0\",\"dp\":\"TEaZvJseYz3EFxeK15qU1htiV07wDk9BMz7g_ZJmbgJ1EmDMszfuMal-8rdOSnUk7fIihFxl71HNdSRwq85cTZ6b2dFPc4pYdV7Dp69FhLztoJ3D2XYWkvRC9E7yu2nK8uhoVUPopX8yaIhhqr67K3Da7ppfDErXUEEC9swSgrM\",\"dq\":\"J_XP4HBbTjOtIaYRFcHrtvkRzhjLR7pVH4dedV6DPYoOyKKcJPbxRLouA-iSjKhhKje7sVkvZ7CtGfmTIGOlQaSjBfDSZjhNOyIjp0SPcj_v9HB-GgDtPpt4c2JhUjCAH4YFH10ImiQImXjC861_mDzKIM5oq-jIPhBC0rxxXqE\",\"qi\":\"exJQqZEtA7p9XxItMAip-OTQ7W6n40xexi8PrJdfEvbrk0aAqO4-ixFyqlQnkwKGQt-IIBgwxjRPwEMMMufd_iLbc0EL1QZN370hSCyqIReGa5qH0W2vvoRf4QfmIiEWumfVWTOb9isCW1nlrPnCkBgGrLxTyZKS_BWwez7eDXQ\",\"enc\":\"A256CBC-HS512\"}]}");

      OIDCClient oidcClient = new OIDCClient(config);

      Map<String, Object> proofs = oidcClient.generateProofs();
      String scope = "openid email";

      Map<String, String[]> query = new HashMap<>();
      query.put("iss", new String[] { "http://localhost:9001/oidc" });

      URI authorizationUrl = oidcClient.getAuthorizationUrl(query, proofs, scope, new HashMap<>());

      assertNotNull(authorizationUrl);
      assertEquals(authorizationUrl.toString(),
          "http://localhost:9001/oidc/auth?request_uri=urn:ietf:params:oauth:request_uri:1duWT28BU4eM4l1cnXgVN");

      // Mock OIDC requests (jwks, token, userinfo)
      stubFor(get(urlEqualTo("/oidc/jwks"))
          .willReturn(aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody(
                  "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"-M_9vqJi0tSYDeXFh3clvZ70ntBosUVT9aqB--2SQiU\",\"alg\":\"PS256\",\"e\":\"AQAB\",\"n\":\"xXGeqFK71mOGUdSSqWr2-DS2oCywcO5TLhLC7QFld-rx6LQ--qmqu7uQgiFO9aFl01MIZF_hs7D1RGX1EmB5odP98vqFVvpBvy3Sse6VZtMccKFtvywNsfWLGRwydzGw9B2s4yWy5ARP2w7fg1X3TnZgtOjtilwvJ1QCXWj3AshXcFj9Mn62z7iPnUcYZCupdyJObaCTcnclLBfUSk4AifkGvyqGplfDpfebLcJWMOUd4mm-Hv2qd9o95WhCfmsEALis8tgxkXTjAUIrS17Fw4-MIEDWFDDEn9bXQkzJ2vYGoKklN5k9_6y3pW95YIX81vvAEiLeRImWI-1q7ka5rw\"},{\"kty\":\"RSA\",\"use\":\"enc\",\"kid\":\"sG0SskqyiA6IWm0Hb3VhmL8TUqSIx_Mqncb3CJNm63c\",\"alg\":\"RSA-OAEP\",\"e\":\"AQAB\",\"n\":\"4LdgDCzIqIV0q2O42B8rXM7WulYJ3gQWJGpElWI4taXb71jPLhbuVphIggmqFmTejVkKGsOVieZoN8CHBkXQq7JmFXbDLHHzqY9uhIsJbNP6i-xRb-rnNPzNy7Vs5I0tpNByi30zQluyO8z0Q3LYK1gOvxAED3jAWfmpcIO1kjlGRxjWeql3Tt6uc3jbt3mqeTsqb7Y5jnO0ee7oHcncWiQvufcGTaOa7NusfTCAcTpWsxoTD3CbmRaVXW0VERpNkzXPpqls3Jned01oDI9F4LkCn03mD2srNUnMElf0AWT_fJ0ZlelBTmZQhV8Luxyoio9DjJDLKxf67CyrJ6VU3Q\"}]}")));

      stubFor(post(urlEqualTo("/oidc/token"))
          .willReturn(aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody(
                  "{\"access_token\":\"NHtB5NG6woOQSeGn5BQr5qAu6ai8B_edu8S9VpfrAXY\",\"expires_in\":60,\"id_token\":\"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii1NXzl2cUppMHRTWURlWEZoM2Nsdlo3MG50Qm9zVVZUOWFxQi0tMlNRaVUifQ.eyJzdWIiOiIzMmYwOTk4ZmM3MTBjNjhjNzY2MWY3M2QxMmJmMDdlOTg3YTRjYjY4OGIzZGZhNDhhNmVlMjdmOTUyNjJlZTIyIiwiZW1haWwiOiJQaGlsaXBITG92ZXR0QG1pa29tb3Rlc3QuY29tIiwiZmFtaWx5X25hbWUiOiJMb3ZldHQiLCJnaXZlbl9uYW1lIjoiUGhpbGlwIiwibm9uY2UiOiJMYk1SNTBJRXVCQmtOWmpPZFhtcURkV2FXWmVXUUg0emtxblBpV1FjNGR1U2FBV2JlZnB3VE9hLXh4eDYxVEljTXJZcWdzNWhrUVJDN0d5MFB0LVN4USIsImF0X2hhc2giOiJibkFTcEN2M2xNLTZ2dzBHZWd0YW1nIiwiYXVkIjoiRjhXOFpLVWl5UlhfMG5vT0xhOTQzIiwiZXhwIjoxNjk4ODc0MDU5LCJpYXQiOjE2OTg4NzM5OTksImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9vaWRjIn0.QLySATBZIUYbJ7fNKCsTNypuF34H4TBjNywy-FB2O-QF0NXrSNIhIwGfJ7K_VHQfYXodkqNxUc-rOmNxU053IaEtlV-tTFhrxEshiD5P5UpMtecBhESac_yG621OS-zH-_NrZLhXELdBLEojAISYODdNh3DXv1ivaoWRHQFBALmWotc7MnIFPUdior1-IocKyn-k6b80KEOx5qTfvXIrmELrlWqsFzJA8DNpKqGPcyBzDjLs26zCbS-jRgvg1jk2I6YT9ywYWitqm5XuzQze-e3A1h9_r1U3eTG2BL4jA9l0X6qNOu602MOCP0aTTLALV74mAkcrQB3_lCWpHnOntQ\",\"scope\":\"openid email profile\",\"token_type\":\"Bearer\"}")));

      stubFor(get(urlEqualTo("/oidc/me"))
          .willReturn(aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody(
                  "{\"sub\":\"32f0998fc710c68c7661f73d12bf07e987a4cb688b3dfa48a6ee27f95262ee22\",\"email\":\"PhilipHLovett@mikomotest.com\",\"family_name\":\"Lovett\",\"given_name\":\"Philip\"}")));

      // Simulate a JWT arrived to the callback endpoint
      query = new HashMap<>();
      query.put("response", new String[] {
          "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJjdHkiOiJKV1QiLCJraWQiOiJ1NjRWc0lCLWN4WDNOSGYxblluMU90QlhtV1dRZlpacDJCVk4xclpMNlhVIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAxL29pZGMiLCJhdWQiOiJKWXJMTzBKal93RGRRUk0ySmlyM2IifQ.RTCfCHa4FB3gdRpzY-jwFcLIAK43fqTjWNMogeElVo7awa6sTkuCotjA_0TyH13R-wzttl_BUPVALnlW9kqdOFuWznkj_erIiFNQTCVIsqm0ZQsFGHBvTDe_lbBYHwwQ1sLUOQExTafE6f5jqrdGN30ylF3HAJJbG3sRR1VBVJdZwck0iar0m5s__iJN0bqlMa-e3jkCyQYJBrKhsMCl1dNm0UnpgpA1Tl5ElVDPByDm9aErN5xe6c5Hw0GTVTKbii2Wk1YXwigTkhrw0dk1xedo8hT1MW90t083An-Y74iU93gJdb4lG6UAxa1bXLpYUJUjHa4dosXSJ22zOcWbaQ.NDyH71DNX_XNMNLYl49cyQ.2LXuEa-vxF4i76N7mKMOkS236Wh_lCP7eksrml_vfIDKea4KuFoHPRhdMUggiJdSS_ybZoyv876Uw-38lTRBaxYp8VSHZCCVdy5uPsr4GTzLt7vWBRw5XQkdNfv8qPpGx15uHpxWLSV_38GaSil__WTnq4RRUmv6IYlZbH4X-a_UojH_po4n98yDolxMQJUtHIWmwQCHH3G8bIiYryy-t79KQfX5s_yLdO6zjC_6MfTAs9EEFkBub2_d-IBujg7RnEGFJU3eLRlOB5W60McrJIe000LrzeE3ahDIY0Xxwy7qXAAXWq1bL0tExNBtLTRpdUCoR35xDwHgh0Mg4FCOcys8KCZtJrCFXhX4z3ctqcR0FIs_cNmxal-3EIUXY8GfvRXyD3pkePFW4Rlr4GTdThpz2rujL3LX6-QXCjmgHVUR-eQj1VDq9fIVC1PqsTh_OpHgwjyiqzWwNIQTnyrIPjKsiRI4n7Bm6UorY0_SEsS71AXw7OivUrTCKtCkzMJzACUtVaU1Hg5DMchqON-ZYArpJQmSQBk8Sz9GFGgT-WBuDMgAkdQOgf4z5PwsjeFf-akLt14BmRYiURbB5kTprEHvRF0eYkiG1yn_AwIGZNneRUh-qcoIotIgi2iazpVA6EpO0FY0WiF9Wh7gF-lrdIqBKTPL2VyMdjjDtWXqx04Q4IIv2hj3oMigSmvVQm1lTetPnvfPNhZ3gTeu9DT6tF-VSy9GvBY6AhNchyb2r-EvFpRfjZDu-ZX4yPKLajdRdNhpg8AqEvT4Uzq0dxKF7GKNB86QnE8kzcFxt1JWQ6ox_fqC2btvzXVveyQC4211CjqFAHKB2fSl33IY8EY2bUT76Gf1s4NcvUgfc_0Uo6026ljIzv8as6iWUPbs_99NYffMXvP3QYC7qHKbYfQjsy37EeBOig0sSw-Yi9de2v1dSbMDl5xlyrWBkAjX2PhzA1Sz9ioU4gxnQ0Z3QzcqXy8Ev1e1djbaPmXa_xwnvYsHn9bl50OyTW0IUdDZy3Oz.C-Yc1Z4TIywcPuzjwVkntTxy-1LCx5TIQ8Aygf2v_Pc" });
      // Exchange the JWT for an access token
      OIDCTokens token = oidcClient.token(query, proofs);
      AccessToken accessToken = token.getAccessToken();
      String userInfo = oidcClient.userinfo(accessToken);
      assertEquals(userInfo,
          "{\"sub\":\"32f0998fc710c68c7661f73d12bf07e987a4cb688b3dfa48a6ee27f95262ee22\",\"given_name\":\"Philip\",\"family_name\":\"Lovett\",\"email\":\"PhilipHLovett@mikomotest.com\"}");
    }
  }
}
