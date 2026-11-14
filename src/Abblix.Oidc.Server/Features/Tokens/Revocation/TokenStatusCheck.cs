// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Refuses a token this server issued that has since been rotated, whose grant family was killed, or that a
/// subject- or session-level cutoff reaches, judged by what is recorded at the tenant the token is validated for.
/// </summary>
/// <remarks>
/// A step of validating the tokens this server issues, run after the token has been found authentic. A token a
/// client or another issuer wrote has nothing recorded about it, so nothing here would refuse it.
/// <para>
/// The two halves come from different stores and answer different questions, which is why the cutoff lives
/// behind <see cref="IRevocationCutoffChecker"/> rather than here: this type asks what is recorded about one
/// token, and that one asks what is recorded about the principal behind it.
/// </para>
/// </remarks>
/// <param name="tokenRegistry">The token registry used to check token status.</param>
/// <param name="cutoffChecker">Decides whether a revocation cutoff reaches this token.</param>
/// <param name="grantRevocation">Revokes the grant of a replayed refresh token.</param>
public sealed class TokenStatusCheck(
	ITokenRegistry tokenRegistry,
	IRevocationCutoffChecker cutoffChecker,
	GrantRevocation grantRevocation)
{
	/// <summary>
	/// <paramref name="token"/> when nothing recorded at <paramref name="tenant"/> refuses it, otherwise the refusal.
	/// </summary>
	/// <param name="tenant">The tenant the token is validated for, whose records are read.</param>
	/// <param name="token">The token, already found authentic.</param>
	/// <param name="options">What the caller validates, which decides whether a cutoff applies.</param>
	public async Task<Result<JsonWebToken, JwtValidationError>> CheckAsync(
		TenantDefinition tenant,
		JsonWebToken token,
		ValidationOptions options)
	{
		// Chain of Responsibility: what is recorded about the principal, then about the token's grant family,
		// then about the token itself; the first refusal answers
		var refusal = await CutoffRefusalAsync(tenant, token, options)
		              ?? await GrantFamilyRefusalAsync(tenant, token)
		              ?? await TokenStatusRefusalAsync(tenant, token);

		return refusal is null ? token : refusal;
	}

	/// <summary>
	/// The refusal a revocation cutoff on the principal behind <paramref name="token"/> produces, if any.
	/// </summary>
	private async Task<JwtValidationError?> CutoffRefusalAsync(
		TenantDefinition tenant,
		JsonWebToken token,
		ValidationOptions options)
	{
		// Checked before the per-token links, and outside them: a cutoff is a fact about the principal
		// rather than about one token, so it must also refuse a token that carries no identifier of its
		// own. Those links are all guarded by jti, which RFC 7519 Section 4.1.7 makes OPTIONAL. Access
		// tokens do carry one - RFC 9068 Section 2.2 makes it REQUIRED for the at+jwt profile they use -
		// so the tokens this placement actually protects are the rest of what this server mints.
		//
		// Only where the caller validates lifetime, which is the same discriminator and not a coincidence: a
		// cutoff says a token is too old to act on, so a caller that has switched lifetime off is saying it
		// reads this token as a reference to something past rather than as authority. The logout endpoint is
		// exactly that - an id_token_hint names the session that just ended, and refusing it because that
		// session was revoked would break the second logout of a session the first one revoked.
		if (!options.HasFlag(ValidationOptions.ValidateLifetime))
			return null;

		return await cutoffChecker.CheckAsync(tenant, token.Payload);
	}

	/// <summary>
	/// The refusal a revoked grant family produces for an identified <paramref name="token"/> exercising it.
	/// </summary>
	private async Task<JwtValidationError?> GrantFamilyRefusalAsync(TenantDefinition tenant, JsonWebToken token)
	{
		// A token exercising a family's authority carries its grant id (Payload.GrantId); the rest leave it
		// null, so the family logic is inert for them. A revoked grant is a kill switch that outlives any single
		// token: once one member's replay trips it, every member of the family - including the currently active
		// refresh token and the access tokens minted beside them - is rejected here on its next use
		// (RFC 9700 section 4.14.2).
		if (token.Payload is not { JwtId: not null, GrantId: { } grantId })
			return null;

		var status = await tokenRegistry.GetStatusAsync(tenant, grantId);
		return status switch
		{
			JsonWebTokenStatus.Revoked => new JwtValidationError(JwtError.TokenRevoked, "Refresh token family was revoked"),
			JsonWebTokenStatus.Unknown or JsonWebTokenStatus.Used => null,
			_ => throw new ArgumentOutOfRangeException(nameof(token), status, "A token status without a family verdict."),
		};
	}

	/// <summary>
	/// The refusal what is recorded about an identified <paramref name="token"/> itself produces, if any.
	/// </summary>
	private async Task<JwtValidationError?> TokenStatusRefusalAsync(TenantDefinition tenant, JsonWebToken token)
	{
		if (token.Payload.JwtId is not { } jwtId)
			return null;

		switch (await tokenRegistry.GetStatusAsync(tenant, jwtId))
		{
			case JsonWebTokenStatus.Used:
				// Replay of a superseded (rotated) token. We cannot tell an attacker from a lagging client,
				// so revoke the whole grant family; the active token dies with it on its next use.
				await grantRevocation.RevokeAsync(tenant, token.Payload);

				return new JwtValidationError(JwtError.TokenAlreadyUsed, "Token was already used");

			case JsonWebTokenStatus.Revoked:
				return new JwtValidationError(JwtError.TokenRevoked, "Token was revoked");

			case JsonWebTokenStatus.Unknown:
				// Nothing is recorded about this token, which is what an ordinary one looks like: the
				// registry holds an entry only once a token has been rotated or revoked. Spelled out
				// rather than left to fall through, because acceptance is the outcome here and a status
				// added later must not inherit it silently. TokenStatusCoverageTests walks the enum and
				// fails when one does.
				break;
		}

		return null;
	}
}
