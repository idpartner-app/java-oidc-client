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

  // public void setClientId(String clientId) {
  //   this.clientId = clientId;
  // }

  public String getClientSecret() {
    return clientSecret;
  }

  // public void setClientSecret(String clientSecret) {
  //   this.clientSecret = clientSecret;
  // }

  public String getRedirectUri() {
    return redirectUri;
  }

  // public void setRedirectUri(String redirectUri) {
  //   this.redirectUri = redirectUri;
  // }

  public String getScope() {
    return scope;
  }

  // public void setScope(String scope) {
  //   this.scope = scope;
  // }

  public int getPort() {
    return port;
  }

  // public void setPort(int port) {
  //   this.port = port;
  // }

  // Getters and Setters for each field
}
