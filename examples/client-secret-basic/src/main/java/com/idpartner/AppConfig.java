package com.idpartner;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AppConfig {
  @JsonProperty("client_id")
  private String clientId;

  @JsonProperty("client_secret")
  private String clientSecret;

  @JsonProperty("redirect_uri")
  private String redirectUri;

  @JsonProperty("scope")
  private String scope;

  @JsonProperty("port")
  private int port;

  public String getClientId() {
    return clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public String getScope() {
    return scope;
  }

  public int getPort() {
    return port;
  }
}
