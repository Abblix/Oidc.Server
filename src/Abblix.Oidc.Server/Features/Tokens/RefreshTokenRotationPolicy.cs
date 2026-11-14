// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// Whether renewing a refresh token of <paramref name="clientInfo"/> spends the token it renews.
	/// </summary>
	/// <param name="tenant">The tenant the client is registered at, whose security profile applies to it.</param>
	/// <param name="clientInfo">The client renewing its refresh token.</param>
	/// <remarks>
	/// The profile and the default policy drop rotation only for a confidential client whose tokens are
	/// sender-constrained, the two controls that replace it; an explicit Reuse is the host's own decision and
	/// drops it for whatever client the host sets it on.
	/// </remarks>
	public static bool Rotates(TenantDefinition tenant, ClientInfo clientInfo)
		=> !ReusesRefreshTokens(clientInfo) && !ProfileForbidsRotation(tenant, clientInfo);

	/// <summary>
	/// Whether <paramref name="clientInfo"/> reuses its refresh tokens under its
	/// <see cref="RefreshTokenOptions.ReusePolicy"/>.
	/// </summary>
	private static bool ReusesRefreshTokens(ClientInfo clientInfo) => clientInfo.RefreshToken.ReusePolicy switch
	{
		RefreshTokenReusePolicy.WhenSenderConstrained => IsAlwaysSenderConstrained(clientInfo),
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
	private static bool IsAlwaysSenderConstrained(ClientInfo clientInfo)
	{
		if (ReceivesTokensOutsideTheTokenEndpoint(clientInfo))
			return false;

		return BindsEveryTokenRequest(clientInfo.TokenEndpointAuthMethod, clientInfo.RequireDPoP);
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
	// keeps rotating
	private static bool BindsEveryTokenRequest(string tokenEndpointAuthMethod, bool requireDPoP)
		=> tokenEndpointAuthMethod switch
		{
			ClientAuthenticationMethods.TlsClientAuth or ClientAuthenticationMethods.SelfSignedTlsClientAuth => true,
			ClientAuthenticationMethods.PrivateKeyJwt => requireDPoP,
			_ => false,
		};
}
