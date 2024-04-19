// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The root of the OIDC configuration. Provides the simplest way to configure and start your OIDC server.
/// </summary>
public record OidcOptions
{
	/// <summary>
	/// Configuration options for OIDC discovery. These options control how the OIDC server advertises its capabilities
	/// and endpoints to clients through the OIDC Discovery mechanism. Proper configuration ensures that clients can
	/// dynamically discover information about the OIDC server, such as URLs for authorization, token, userinfo, and
	/// JWKS endpoints, supported scopes, response types, and more.
	/// </summary>
	public DiscoveryOptions Discovery { get; set; } = new();

	/// <summary>
	/// Represents the unique identifier of the OIDC server.
	/// It is recommended to use a URL that is controlled by the entity operating the OIDC server, and it should be
	/// consistent across different environments to maintain trust with client applications.
	/// </summary>
	public string? Issuer { get; set; }

	/// <summary>
	/// A collection of client configurations supported by this OIDC server. Each <see cref="ClientInfo"/> object
	/// defines the settings and capabilities of a registered client, including client ID, client secrets,
	/// redirect URIs, and other OAuth2/OIDC parameters. Proper client configuration is essential for securing client
	/// applications and enabling them to interact with the OIDC server according to the OAuth2 and OIDC specifications.
	/// </summary>
	public IEnumerable<ClientInfo> Clients { get; set; } = Array.Empty<ClientInfo>();

	/// <summary>
	/// The URL to a user interface or service that allows users to select an account during the authentication process.
	/// This is useful in scenarios where users have multiple accounts and need to choose which one to use for signing in.
	/// </summary>
	public Uri? AccountSelectionUri { get; set; }

	/// <summary>
	/// The URL to a user interface or service for obtaining user consent during the authentication process. Consent is
	/// often required when the client application requests access to user data or when sharing information between
	/// different parties. This URI should point to a page or API that can manage consent workflows and communicate
	/// the user's decisions back to the OIDC server.
	/// </summary>
	public Uri? ConsentUri { get; set; }

	/// <summary>
	/// The URL to a user interface or service for handling additional interactions required during the authentication
	/// process. This can include multiple factor authentication, user consent, or any custom interaction required by
	/// the authentication flow. The OIDC server can redirect users to this URI when additional interaction is needed.
	/// </summary>
	public Uri? InteractionUri { get; set; }

	/// <summary>
	/// The URL to initiate the login process. This URI is typically used in scenarios where the OIDC server needs to
	/// direct users to a specific login interface or when integrating with external identity providers. Configuring
	/// this URI allows the OIDC server to delegate the initial user authentication step to another service or UI.
	/// </summary>
	public Uri? LoginUri { get; set; }

	/// <summary>
	/// The name of the parameter used by the OIDC server to pass the authorization request identifier. This parameter
	/// name is used in URLs and requests to reference specific authorization requests, especially in advanced features
	/// like Pushed Authorization Requests (PAR). Customizing this parameter name can help align with specific client
	/// requirements or naming conventions.
	/// </summary>
	public string RequestUriParameterName { get; set; } = AuthorizationRequest.Parameters.RequestUri;

	/// <summary>
	/// Specifies which OIDC endpoints are enabled on the server. This property allows for fine-grained control over
	/// the available functionality, enabling or disabling specific endpoints based on the server's role, security
	/// considerations, or operational requirements. By default, all endpoints are enabled.
	/// </summary>
	public OidcEndpoints EnabledEndpoints { get; set; } = OidcEndpoints.All;

	/// <summary>
	/// The collection of JSON Web Keys (JWK) used for signing tokens issued by the OIDC server.
	/// Signing tokens is a critical security measure that ensures the integrity and authenticity of the tokens.
	/// These keys are used to digitally sign ID tokens, access tokens, and other JWTs issued by the server,
	/// allowing clients to verify that the tokens have not been tampered with and were indeed issued by this server.
	/// It is recommended to rotate these keys periodically to maintain the security of the token signing process.
	/// </summary>
	public IReadOnlyCollection<JsonWebKey> SigningKeys { get; set; } = Array.Empty<JsonWebKey>();

	/// <summary>
	/// Options related to the check session mechanism in OIDC. This configuration controls how the OIDC server manages
	/// session state information, allowing clients to monitor the login session's status. Properly configuring these
	/// options ensures that clients can react to session changes (e.g., logout) in a timely and secure manner.
	/// </summary>
	public CheckSessionCookieOptions CheckSessionCookie { get; set; } = new();

	/// <summary>
	/// The duration after which a login session expires. This setting determines how long a user's authentication
	/// session remains valid before requiring re-authentication. Configuring this duration is essential for balancing
	/// security concerns with usability, particularly in environments with varying security requirements.
	/// </summary>
	public TimeSpan LoginSessionExpiresIn { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// Configuration options for registering new clients dynamically in the OIDC server. These options define default
	/// values and constraints for new client registrations, facilitating dynamic and secure client onboarding processes.
	/// </summary>
	public NewClientOptions NewClientOptions { get; init; } = new();

	/// <summary>
	/// The collection of JSON Web Keys (JWK) used for encrypting tokens or sensitive information sent to the clients.
	/// Encryption is essential for protecting sensitive data within tokens, especially when tokens are passed through
	/// less secure channels or when storing tokens at the client side. These keys are utilized to encrypt ID tokens and,
	/// optionally, access tokens when the OIDC server sends them to clients. Clients use the corresponding public keys
	/// to decrypt the tokens and access the contained claims.
	/// </summary>
	public IReadOnlyCollection<JsonWebKey> EncryptionKeys { get; set; } = Array.Empty<JsonWebKey>();

	/// <summary>
	/// The duration for which a Pushed Authorization Request (PAR) is valid. PAR is a security enhancement that allows
	/// clients to pre-register authorization requests directly with the authorization server. This duration specifies
	/// the maximum time a pre-registered request is considered valid, balancing the need for security with usability
	/// in completing the authorization process.
	/// </summary>
	public TimeSpan PushedAuthorizationRequestExpiresIn { get; set; } = TimeSpan.FromMinutes(1);

	/// <summary>
	/// A JWT used for licensing and configuration validation of the OIDC service. This token contains claims that the
	/// OIDC service uses to validate its configuration, features, and licensing status, ensuring the service operates
	/// within its licensed capabilities. Proper validation of this token is crucial for the service's legal and functional
	/// compliance.
	/// </summary>
	public string? LicenseJwt { get; set; }

	public int AuthorizationCodeLength { get; set; } = 64;

	public int RequestUriLength { get; set; } = 64;
}
