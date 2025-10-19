// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
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
		TimeProvider clock,
		ITokenIdGenerator tokenIdGenerator,
		IAuthServiceJwtFormatter serviceJwtFormatter)
	{
		_issuerProvider = issuerProvider;
		_clock = clock;
		_tokenIdGenerator = tokenIdGenerator;
		_serviceJwtFormatter = serviceJwtFormatter;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly TimeProvider _clock;
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
		var issuedAt = _clock.GetUtcNow();

		var accessToken = new JsonWebToken
		{
			Header =
			{
				Type = JwtTypes.AccessToken,
				Algorithm = SigningAlgorithms.RS256,
			},
			Payload =
			{
				JwtId = _tokenIdGenerator.GenerateTokenId(),
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + clientInfo.AccessTokenExpiresIn,
				Issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()),
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
	/// <returns>A task that returns the <see cref="AuthSession"/> and <see cref="AuthorizationContext"/>
	/// derived from the token.</returns>
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
