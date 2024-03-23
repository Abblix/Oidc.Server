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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Contains information about a client in an OAuth2/OpenID Connect context.
/// </summary>
/// <remarks>
/// This record encapsulates the details necessary to identify and configure the behavior of a client application
/// within an OAuth2 or OpenID Connect framework. It includes identifiers, secrets, and configuration options
/// that dictate how the client interacts with the authorization server and is authenticated or authorized during
/// the token issuance process.
/// </remarks>
public record ClientInfo(string ClientId)
{
    /// <summary>
    /// Identifies the client's unique identifier as recognized by the authorization server.
    /// It is used in various OAuth 2.0 and OpenID Connect flows to represent the client application.
    /// </summary>
    public string ClientId { get; set; } = ClientId;

    /// <summary>
    /// Classifies the client based on its ability to securely maintain a client secret.
    /// This classification influences the authorization flow and token endpoint authentication method that
    /// the client can utilize. Public clients, such as mobile or desktop applications, cannot securely store secrets,
    /// while confidential clients, like server-side web applications, can.
    /// </summary>
    public ClientType ClientType { get; set; } = ClientType.Public;

    /// <summary>
    /// A collection of secrets associated with the client, used for authenticating the client to the authorization server.
    /// Multiple secrets can be provided for added security.
    /// </summary>
    public ClientSecret[]? ClientSecrets { get; set; }

    /// <summary>
    /// Specifies the URIs where the user-agent can be redirected after authorization.
    /// These URIs must be pre-registered and match the redirect URI provided in the authorization request.
    /// </summary>
    public Uri[] RedirectUris { get; set; } = Array.Empty<Uri>();

    /// <summary>
    /// Specifies the URIs where the user-agent can be redirected after logging out from the client application.
    /// This allows for a seamless user experience upon logout.
    /// </summary>
    public Uri[] PostLogoutRedirectUris { get; set; } = Array.Empty<Uri>();

    /// <summary>
    /// Indicates whether the client is to use Proof Key for Code Exchange (PKCE) in the authorization code flow,
    /// enhancing security for public clients.
    /// </summary>
    public bool PkceRequired { get; set; } = true;

    /// <summary>
    /// Indicates if the client is allowed to use the "plain" method for PKCE.
    /// It is recommended to use stronger methods like "S256" for enhanced security.
    /// </summary>
    public bool PlainPkceAllowed { get; set; } = false;

    /// <summary>
    /// The validity period of an authorization code issued to this client.
    /// Shorter durations are recommended for higher security.
    /// </summary>
    public TimeSpan AuthorizationCodeExpiresIn { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Specifies the lifetime of access tokens issued to this client.
    /// Shorter access token lifetimes reduce the risk of token leakage.
    /// </summary>
    public TimeSpan AccessTokenExpiresIn { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Configures the behavior and properties of refresh tokens issued to this client,
    /// such as their expiration and renewal policies.
    /// </summary>
    public RefreshTokenOptions RefreshToken { get; set; } = new();

    /// <summary>
    /// Determines the validity period of identity tokens issued to this client.
    /// Shorter durations enhance security by reducing the window of misuse.
    /// </summary>
    public TimeSpan IdentityTokenExpiresIn { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Options for configuring front-channel logout behavior, allowing the client to participate in logout requests
    /// initiated by other clients.
    /// </summary>
    public FrontChannelLogoutOptions? FrontChannelLogout { get; set; }

    /// <summary>
    /// Options for configuring back-channel logout behavior, enabling the server to directly notify
    /// the client of logout events.
    /// </summary>
    public BackChannelLogoutOptions? BackChannelLogout { get; set; }

    /// <summary>
    /// Defines the response types that the client is permitted to use.
    /// This controls how tokens are issued in response to an authorization request.
    /// </summary>
    public string[][] AllowedResponseTypes { get; set; } = { new[] { ResponseTypes.Code } };

    /// <summary>
    /// Specifies the grant types the client is authorized to use when obtaining tokens from the token endpoint.
    /// </summary>
    public string[] AllowedGrantTypes { get; set; } = { GrantTypes.AuthorizationCode };

    /// <summary>
    /// Allows the client to request tokens that enable access to the user's resources while they are offline.
    /// </summary>
    public bool OfflineAccessAllowed { get; set; } = false;

    /// <summary>
    /// The set of JSON Web Keys used by the client, typically for signing request objects and decrypting
    /// identity tokens or encrypted user information.
    /// </summary>
    public JsonWebKeySet? Jwks { get; set; }

    /// <summary>
    /// The publicly accessible URL where the client's JSON Web Key Set (JWKS) can be retrieved.
    /// </summary>
    public Uri? JwksUri { get; set; }

    /// <summary>
    /// Specifies the algorithm that must be used for signing identity token responses issued to this client.
    /// </summary>
    public string IdentityTokenSignedResponseAlgorithm { get; set; } = SigningAlgorithms.RS256;

    /// <summary>
    /// Controls whether claims about the authenticated user are included directly in the identity token
    /// instead of being obtained separately via the UserInfo endpoint.
    /// </summary>
    public bool ForceUserClaimsInIdentityToken { get; set; } = false;

    /// <summary>
    /// Describes how the client authenticates to the token endpoint.
    /// Common methods include client_secret_basic and client_secret_post.
    /// </summary>
    public string TokenEndpointAuthMethod { get; set; } = ClientAuthenticationMethods.ClientSecretBasic;

    /// <summary>
    /// Determines the algorithm used for signing responses from the UserInfo endpoint.
    /// This can enhance the security of transmitted user information.
    /// </summary>
    public string UserInfoSignedResponseAlgorithm { get; set; } = SigningAlgorithms.None;

    /// <summary>
    /// A URL pointing to the client's policy documentation, providing transparency on how user data
    /// is handled and protected.
    /// </summary>
    public Uri? PolicyUri { get; set; }

    /// <summary>
    /// A URL pointing to the client's terms of service, outlining the legal agreement between the user
    /// and the service provider.
    /// </summary>
    public Uri? TermsOfServiceUri { get; set; }

    /// <summary>
    /// A URL pointing to an image file representing the client's logo, which can be displayed in user interfaces
    /// during authorization.
    /// </summary>
    public Uri? LogoUri { get; set; }

    /// <summary>
    /// A URI that allows third-party sites to initiate a login by the client, facilitating integrations and
    /// single sign-on scenarios.
    /// </summary>
    public Uri? InitiateLoginUri { get; set; }

    /// <summary>
    /// Specifies the subject identifier type requested by the client. This influences how the authorization server
    /// represents the authenticated user's identity to the client, affecting privacy and uniqueness across different
    /// clients. Common types include "public" and "pairwise".
    /// </summary>
    public string? SubjectType { get; set; } = SubjectTypes.Public;

    /// <summary>
    /// Used in conjunction with pairwise subject identifiers to calculate the subject value returned to the client.
    /// This field is particularly relevant for ensuring user privacy by providing a different subject identifier
    /// to each client, even if it's the same end-user. It typically contains a URL or a unique identifier
    /// representing the client's sector.
    /// </summary>
    public string? SectorIdentifier { get; set; }
}
