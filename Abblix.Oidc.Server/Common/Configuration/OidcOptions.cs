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

using System.Security.Cryptography.X509Certificates;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The root of the OIDC configuration. Provides the simplest way to configure and start your OIDC server.
/// </summary>
public record OidcOptions
{
	/// <summary>
	/// The OIDC discovery options.
	/// </summary>
	public DiscoveryOptions Discovery { get; set; } = new();

	/// <summary>
	/// The issuer identifier to be used in tokens. It is useful for scenarios where the issuer
	/// needs to be consistent and predefined, such as environments with multiple hosts.
	/// </summary>
	public string? Issuer { get; set; }

	/// <summary>
	/// The client configurations supported by the OIDC server.
	/// </summary>
	public IEnumerable<ClientInfo> Clients { get; set; } = Array.Empty<ClientInfo>();

	/// <summary>
	/// The URI for account selection during authentication.
	/// </summary>
	public Uri? AccountSelectionUri { get; set; }

	/// <summary>
	/// The URI for obtaining user consent during authentication.
	/// </summary>
	public Uri? ConsentUri { get; set; }

	/// <summary>
	/// The URI for handling interactions during the authentication process.
	/// </summary>
	public Uri? InteractionUri { get; set; }

	/// <summary>
	/// The URI for initiating a login process.
	/// </summary>
	public Uri? LoginUri { get; set; }

	/// <summary>
	/// The parameter name for authorization request identifier.
	/// </summary>
	public string RequestUriParameterName { get; set; } = AuthorizationRequest.Parameters.RequestUri;

	/// <summary>
	/// Specifies which OIDC endpoints are enabled.
	/// </summary>
	public OidcEndpoints EnabledEndpoints { get; set; } = OidcEndpoints.All;

	/// <summary>
	/// The certificates used for signing tokens.
	/// </summary>
	public IReadOnlyCollection<X509Certificate2> SigningCertificates { get; set; } = Array.AsReadOnly(Array.Empty<X509Certificate2>());

	/// <summary>
	/// The options related to the check session cookie.
	/// </summary>
	public CheckSessionCookieOptions CheckSessionCookie { get; set; } = new();

	/// <summary>
	/// The duration of a login session's expiration.
	/// </summary>
	public TimeSpan LoginSessionExpiresIn { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// Indicates support for claims parameters in requests.
	/// </summary>
	public bool ClaimsParameterSupported { get; set; } = true;

	/// <summary>
	/// A list of scopes supported by the service.
	/// </summary>
	public IList<string> ScopesSupported { get; set; } = new List<string>
	{
		Scopes.OpenId,
		Scopes.Profile,
		Scopes.Email,
		Scopes.Phone,
		Scopes.Address,
		Scopes.OfflineAccess,
	};

	/// <summary>
	/// The claims supported by the service.
	/// </summary>
	public IList<string> ClaimsSupported { get; set; } = new List<string>
	{
		JwtClaimTypes.Subject,
		JwtClaimTypes.Email,
		JwtClaimTypes.EmailVerified,
		JwtClaimTypes.PhoneNumber,
		JwtClaimTypes.PhoneNumberVerified,
	};

	/// <summary>
	/// The response types supported by the service.
	/// </summary>
	public IList<string> ResponseTypesSupported { get; set; } = new List<string>
	{
		ResponseTypes.Code,
		ResponseTypes.Token,
		ResponseTypes.IdToken,
		string.Join(" ", ResponseTypes.IdToken, ResponseTypes.Token),
		string.Join(" ", ResponseTypes.Code, ResponseTypes.IdToken),
		string.Join(" ", ResponseTypes.Code, ResponseTypes.Token),
		string.Join(" ", ResponseTypes.Code, ResponseTypes.IdToken, ResponseTypes.Token),
	};

	/// <summary>
	/// The response modes supported by the service.
	/// </summary>
	public IList<string> ResponseModesSupported { get; set; } = new List<string>
	{
		ResponseModes.FormPost,
		ResponseModes.Query,
		ResponseModes.Fragment,
	};

	/// <summary>
	/// A list of algorithms supported for signing ID tokens.
	/// </summary>
	public IList<string> IdTokenSigningAlgorithmValuesSupported { get; set; } = new List<string>
	{
		SigningAlgorithms.None,
		SigningAlgorithms.RS256,
	};

	/// <summary>
	/// A list of subject types supported by the OIDC service.
	/// </summary>
	public IList<string> SubjectTypesSupported { get; set; } = new List<string>
	{
		SubjectTypes.Public,
		SubjectTypes.Pairwise,
	};

	/// <summary>
	/// A list of supported methods for code challenge in PKCE (Proof Key for Code Exchange).
	/// </summary>
	public IList<string> CodeChallengeMethodsSupported { get; set; } = new List<string>
	{
		CodeChallengeMethods.Plain,
		CodeChallengeMethods.S256,
	};

	/// <summary>
	/// Indicates whether the request parameter is supported by the OIDC service.
	/// </summary>
	public bool RequestParameterSupported { get; set; } = true;

	/// <summary>
	/// A list of prompt values supported by the OIDC service.
	/// </summary>
	public IList<string> PromptValuesSupported { get; set; } = new List<string>
	{
		Prompts.None,
		Prompts.Login,
		Prompts.Consent,
		Prompts.SelectAccount,
		Prompts.Create,
	};

	/// <summary>
	/// Options for configuring a new client in the OIDC service.
	/// </summary>
	public NewClientOptions NewClientOptions { get; init; } = new();

	/// <summary>
	/// A list of algorithms supported for signing UserInfo responses.
	/// </summary>
	public IList<string> UserInfoSigningAlgValuesSupported { get; set; } = new List<string>
	{
		SigningAlgorithms.None,
		SigningAlgorithms.RS256,
	};

	/// <summary>
	/// A list of algorithms supported for signing request objects.
	/// </summary>
	public IList<string> RequestObjectSigningAlgValuesSupported { get; set; } = new List<string>
	{
		SigningAlgorithms.None,
		SigningAlgorithms.RS256,
	};

	/// <summary>
	/// The encryption certificates for the OpenID Connect service tokens.
	/// </summary>
	public IList<X509Certificate2> EncryptionCertificates { get; set; } = new List<X509Certificate2>();

	/// <summary>
	/// The duration for which a pushed authorization request (PAR) is considered valid.
	/// </summary>
	/// <remarks>
	/// This property defines the lifespan of a pushed authorization request. Pushed authorization requests are
	/// a security feature in OIDC that allows clients to send authorization requests directly to the authorization
	/// server via a backchannel connection, rather than through the user's browser. This duration specifies
	/// how long the server should consider the request valid after it has been received. It is important to balance
	/// security and usability when configuring this value, ensuring that requests are valid long enough for users
	/// to complete the authentication process without leaving too large a window for potential misuse.
	/// </remarks>
	public TimeSpan PushedAuthorizationRequestExpiresIn { get; set; } = TimeSpan.FromMinutes(1);

	/// <summary>
	/// The JWT used for licensing and configuration validation of the OIDC service.
	/// </summary>
	/// <remarks>
	/// This property holds a JSON Web Token (JWT) that the OIDC service uses to validate its configuration and
	/// licensing status. The token typically contains claims that the service decodes to determine the features
	/// and capabilities that are enabled, based on the licensing agreement. Proper validation of this token
	/// is crucial for ensuring that the service operates within the terms of its licensing and has access
	/// to the correct set of features. The format and content of this token are determined by the service provider
	/// and may include information such as the license expiry date, the licensed feature set and other relevant data.
	/// </remarks>
	public string? LicenseJwt { get; set; }
}
