# client_secret_basic flow using ruby_oidc_client lib

## Prerequisites

1. [Create an IDPartner Account](https://console.idpartner.com).
1. [Create an Application (Client Secret)](https://docs.idpartner.com/documentation/relying-party-user-guide/registering-your-app#create-an-application).
1. Ensure the following properties are set:
   - Origin URL: http://localhost:3001/button/oauth
   - Redirect URL: http://localhost:3001/button/oauth/callback
1. Grab the "Client ID" and the "Client Secret" to update the following parts in your code:
   1. [Update CHANGE_ME_CLIENT_ID in the configuration file](./config.json)
   1. [Update CHANGE_ME_CLIENT_SECRET in the configuration file](./config.json)

   Aditionally you optionally can configure the next steps:
   1. [Update the "redirect_uri" in the configuration file](./config.json)

## Running the project

1. Run: `mvn install`
1. Run: `mvn spring-boot:run`
1. Access http://localhost:3001
1. Click the "Choose your ID Partner" button
1. Search for "Mikomo Bank"
1. Use these test credentials `mikomo_10/mikomo_10`
