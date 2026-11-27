// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Decides whether a client's refresh tokens rotate, that is, whether renewing one spends it.
/// </summary>
public static class RefreshTokenRotationPolicy
{
	/// <summary>
	/// Whether renewing <paramref name="refreshToken"/> of <paramref name="clientInfo"/> spends it.
	/// </summary>
	/// <param name="tenant">The tenant the client is registered at, whose security profile applies to it.</param>
	/// <param name="clientInfo">The client renewing its refresh token.</param>
	/// <param name="refreshToken">The payload of the refresh token presented for renewal.</param>
	/// <remarks>
	/// The profile and the default policy reuse tokens only of a confidential client whose tokens are
	/// sender-constrained, the two controls that replace rotation; an explicit Reuse reuses the tokens of any client,
	/// and <see cref="MustRotate"/> decides over both.
	/// </remarks>
	public static bool Rotates(TenantDefinition tenant, ClientInfo clientInfo, JsonWebTokenPayload refreshToken)
		=> (!ReusesRefreshTokens(tenant, clientInfo) && !ProfileForbidsRotation(tenant, clientInfo)) ||
		   MustRotate(clientInfo, refreshToken);

	/// <summary>
	/// Whether <paramref name="refreshToken"/> of <paramref name="clientInfo"/> rotates over the client's policy and
	/// profile.
	/// </summary>
	/// <remarks>
	/// RFC 9700 section 2.2.2: "Refresh tokens for public clients MUST be sender-constrained or use refresh token
	/// rotation", and section 4.14.2 names the two ways. A public client authenticates no token request, so only a DPoP
	/// key binds its refresh token: the token carries the key's thumbprint, and every refresh must present a proof of
	/// that key (RFC 9449 section 5). The decision is the presented token's binding, which a client's current
	/// registration does not change. A certificate binds nothing here, since a public client presenting none is issued
	/// an unbound token.
	/// </remarks>
	internal static bool MustRotate(ClientInfo clientInfo, JsonWebTokenPayload refreshToken)
		=> clientInfo.ClientType == ClientType.Public &&
		   refreshToken is not { Confirmation.JwkThumbprint: { Length: > 0 } };

	/// <summary>
	/// Whether <paramref name="clientInfo"/> declares Reuse while a refresh token issued to it now can come without a
	/// DPoP binding, which <see cref="MustRotate"/> rotates.
	/// </summary>
	/// <remarks>
	/// A public client not requiring DPoP is issued a bound token only for a request that happens to carry a proof.
	/// </remarks>
	internal static bool DeclaresReuseWithoutDPoP(ClientInfo clientInfo)
		=> clientInfo is
		{
			ClientType: ClientType.Public,
			RequireDPoP: false,
			RefreshToken.ReusePolicy: RefreshTokenReusePolicy.Reuse,
		};

	/// <summary>
	/// Whether <paramref name="clientInfo"/> reuses its refresh tokens under its
	/// <see cref="RefreshTokenOptions.ReusePolicy"/>.
	/// </summary>
	private static bool ReusesRefreshTokens(TenantDefinition tenant, ClientInfo clientInfo)
		=> clientInfo.RefreshToken.ReusePolicy switch
	{
		RefreshTokenReusePolicy.WhenSenderConstrained => IsAlwaysSenderConstrained(tenant, clientInfo),
		RefreshTokenReusePolicy.Reuse => true,
		RefreshTokenReusePolicy.Rotate => false,
		var policy => throw new InvalidOperationException(
			$"Unknown {nameof(RefreshTokenOptions.ReusePolicy)} value {policy} for the client {clientInfo.ClientId}."),
	};

	/// <summary>
	/// Whether the security profile <paramref name="clientInfo"/> is held to forbids rotating its refresh tokens.
	/// </summary>
	/// <remarks>
	/// FAPI 2.0 section 5.3.2.1 forbids rotation for a client held to it, because a confidential client with a
	/// sender-constrained token gains nothing from rotating while losing its session whenever it fails to store the
	/// token it was handed. The profile decides over the client's own policy, except for a client registered to
	/// receive tokens outside the token endpoint: the profile checks the binding only there, so such a client's
	/// tokens are not sender-constrained and the reason for dropping rotation does not hold.
	/// </remarks>
	private static bool ProfileForbidsRotation(TenantDefinition tenant, ClientInfo clientInfo)
		=> SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile).ForbidRefreshTokenRotation &&
		   !ReceivesTokensOutsideTheTokenEndpoint(clientInfo);

	/// <summary>
	/// Whether every access token of <paramref name="clientInfo"/> is bound to a key the client proves, as
	/// <see cref="RefreshTokenReusePolicy.WhenSenderConstrained"/> explains.
	/// </summary>
	private static bool IsAlwaysSenderConstrained(TenantDefinition tenant, ClientInfo clientInfo)
	{
		if (ReceivesTokensOutsideTheTokenEndpoint(clientInfo))
			return false;

		return BindsEveryTokenRequest(
			clientInfo.TokenEndpointAuthMethod,
			clientInfo.RequireDPoP,
			CertificateBoundAccessTokens.AreIssuedTo(
				clientInfo, SecurityProfileRequirements.For(clientInfo, tenant.DefaultSecurityProfile)));
	}

	/// <summary>
	/// Whether <paramref name="clientInfo"/> is registered to receive an access token that no token request binds:
	/// one delivered by CIBA push, or one returned from the authorization endpoint for a response type that includes
	/// <c>token</c>.
	/// </summary>
	private static bool ReceivesTokensOutsideTheTokenEndpoint(ClientInfo clientInfo)
		=> clientInfo.BackChannelTokenDeliveryMode is BackchannelTokenDeliveryModes.Push ||
		   clientInfo.EffectiveResponseTypes.Any(responseType => responseType.Contains(ResponseTypes.Token));

	// The set of authentication methods is open, since a host registers its own authenticators, so the catch-all arm
	// is the rule rather than a fallback: a method this library cannot name is not known to bind its tokens, and
	// keeps rotating. A certificate authenticates every request of a mutual-TLS client, but binds its token only when
	// the client is bound to certificate-bound tokens; otherwise a required DPoP proof binds it
	private static bool BindsEveryTokenRequest(string tokenEndpointAuthMethod, bool requireDPoP, bool certificateBound)
		=> tokenEndpointAuthMethod switch
		{
			ClientAuthenticationMethods.TlsClientAuth or ClientAuthenticationMethods.SelfSignedTlsClientAuth =>
				certificateBound || requireDPoP,
			ClientAuthenticationMethods.PrivateKeyJwt => requireDPoP,
			_ => false,
		};
}
