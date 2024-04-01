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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Clock;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Manages the lifecycle of access tokens for authenticated users, facilitating the creation of tokens with embedded
/// authorization details and the authentication of requests using these tokens. Utilizes issuer information,
/// current time, unique token identifiers, and JWT formatting to generate secure and compliant access tokens.
/// </summary>
internal class AccessTokenService : IAccessTokenService
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AccessTokenService"/>, responsible for generating and validating
	/// access tokens.
	/// </summary>
	/// <param name="issuerProvider">The provider responsible for determining the issuer (iss) claim in the token,
	/// which identifies the authorization server that issued the token.</param>
	/// <param name="clock">The service used to obtain the current time, ensuring accurate token expiration and
	/// issuance timestamps.</param>
	/// <param name="tokenIdGenerator">The service responsible for generating unique identifiers (jti) for each token,
	/// enhancing security by enabling token revocation and tracking capabilities.</param>
	/// <param name="serviceJwtFormatter">The formatter used for encoding the JSON Web Token (JWT), ensuring it meets
	/// the standards required for secure transmission and validation.</param>
	public AccessTokenService(
		IIssuerProvider issuerProvider,
		IClock clock,
		ITokenIdGenerator tokenIdGenerator,
		IAuthServiceJwtFormatter serviceJwtFormatter)
	{
		_issuerProvider = issuerProvider;
		_clock = clock;
		_tokenIdGenerator = tokenIdGenerator;
		_serviceJwtFormatter = serviceJwtFormatter;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly IClock _clock;
	private readonly ITokenIdGenerator _tokenIdGenerator;
	private readonly IAuthServiceJwtFormatter _serviceJwtFormatter;

	/// <summary>
	/// Asynchronously generates a new access token incorporating the authentication session and authorization context
	/// of the user, along with client-specific settings. This token is crafted using standard JWT practices,
	/// ensuring it aligns with OAuth 2.0 and OpenID Connect requirements.
	/// </summary>
	/// <param name="authSession">Details of the user's current authentication session, including subject and
	/// authentication time.</param>
	/// <param name="authContext">Context providing authorization details such as requested scopes and permissions.
	/// </param>
	/// <param name="clientInfo">Client-specific information, including token expiration settings and required JWT
	/// algorithms.</param>
	/// <returns>A task that resolves to an <see cref="EncodedJsonWebToken"/>, representing the newly minted access
	/// token.</returns>
	/// <remarks>
	/// The generated access token includes a unique identifier and timestamps to manage its lifecycle. It also encodes
	/// the issuer's information, ensuring that the token can be validated against the issuing authority. This method
	/// leverages provided services to dynamically generate compliant tokens suited for various authorization needs.
	/// </remarks>
	public async Task<EncodedJsonWebToken> CreateAccessTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo)
	{
		var issuedAt = _clock.UtcNow;

		var accessToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.AccessToken,
				Algorithm = SigningAlgorithms.RS256,
			},
			Payload =
			{
				JwtId = _tokenIdGenerator.NewId(),
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + clientInfo.AccessTokenExpiresIn,
				Issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()),
				Audiences = new[] { clientInfo.ClientId },
			},
		};

		authSession.ApplyTo(accessToken.Payload);
		authContext.ApplyTo(accessToken.Payload);

		return new EncodedJsonWebToken(accessToken, await _serviceJwtFormatter.FormatAsync(accessToken));
	}

	/// <summary>
	/// Validates the provided access token and extracts the associated authentication session and authorization context.
	/// This process authenticates the token bearer and retrieves their authorization details, enabling secure resource
	/// access.
	/// </summary>
	/// <param name="accessToken">The access token to be authenticated and analyzed.</param>
	/// <returns>A task that, when completed, yields a tuple containing the <see cref="AuthSession"/> and
	/// <see cref="AuthorizationContext"/> derived from the token.</returns>
	/// <remarks>
	/// This method facilitates the secure validation of access tokens, ensuring that only tokens issued by the trusted
	/// authority and not tampered with are accepted. It decodes embedded claims to reconstruct the original
	/// authorization and authentication details, supporting secure and informed access control decisions.
	/// </remarks>
	public Task<(AuthSession, AuthorizationContext)> AuthenticateByAccessTokenAsync(JsonWebToken accessToken)
	{
		var authSession = accessToken.Payload.ToAuthSession();
		var authorizationContext = accessToken.Payload.ToAuthorizationContext();
		return Task.FromResult((authSession, authorizationContext));
	}
}
