# OidcClient

OidcClient is a maven package that simplifies OpenID Connect client operations. This package provides a set of functionalities to interact with OIDC providers, facilitating authentication and authorization processes.

## Installation

You can install the `oidc-client` gem by executing the following command:

```bash
$ mvn install
```

Alternatively, if you are using pom, add these lines to your application's pom.xml:

```ruby
<dependency>
	<groupId>com.idpartner</groupId>
	<artifactId>oidc-client</artifactId>
	<version>0.0.1</version>
</dependency>
```

And then execute:

```bash
$ mvn install
```

## Usage

Please check the [examples folder](./examples/)

### Running Tests

- Ensure the port 9001 is **available**
- After checking out the repo, install the necessary dependencies and run the tests by executing:

```bash
$ mvn test
```

## Release

- Ensure the port 9001 is **available**
- Get the GPG key and passphrase
- Import it to your local and set it as the default key
- copy the [settings.xml.example](./settings.xml) to `~/.m2/settings.xml`. [More details](https://central.sonatype.org/publish/publish-maven/#distribution-management-and-authentication)
- Define the next environment variables:
	- OSSRH_USERNAME
	- OSSRH_PASSWORD
	- GPG_KEY_ID
	- GPG_PASSPHRASE
- Go to the project root folder and execute: `mvn clean deploy -P ossrh`

## Contributing

Bug reports and pull requests are welcome on GitHub at [https://github.com/idpartner-app/java-oidc-client](https://github.com/idpartner-app/java-oidc-client).

## License

This package is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
