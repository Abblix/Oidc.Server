// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Enhances the functionality of an existing <see cref="IJsonWebTokenValidator"/> by adding token revocation validation capabilities.
/// This decorator checks whether the JSON Web Token (JWT) has been revoked or used before and, if so, invalidates the token.
/// It utilizes an <see cref="ITokenRegistry"/> to check the token's status and an inner <see cref="IJsonWebTokenValidator"/>
/// for initial token validation.
/// </summary>
/// <param name="tokenRegistry">The token registry used to check token status.</param>
/// <param name="cutoffRegistry">The registry of subject- and session-level revocation cutoffs.</param>
/// <param name="innerValidator">The inner validator for initial token validation.</param>
public class TokenStatusValidatorDecorator(
	ITokenRegistry tokenRegistry,
	IRevocationCutoffRegistry cutoffRegistry,
	IJsonWebTokenValidator innerValidator) : IJsonWebTokenValidator
{
	/// <summary>
	/// Forwards the set of JWS signing algorithms accepted by the inner validator (RFC 7518 §3.1
	/// names such as <c>RS256</c>, <c>PS256</c>, <c>ES256</c>); revocation checking does not
	/// influence which algorithms are supported.
	/// </summary>
	public IEnumerable<string> SigningAlgorithmsSupported => innerValidator.SigningAlgorithmsSupported;

	/// <summary>
	/// Forwards the JWE key-management algorithms accepted by the inner validator; revocation checking
	/// does not influence which encryption algorithms are supported.
	/// </summary>
	public IEnumerable<string> EncryptionAlgorithmsSupported => innerValidator.EncryptionAlgorithmsSupported;

	/// <summary>
	/// Forwards the JWE content-encryption algorithms accepted by the inner validator; revocation checking
	/// does not influence which encryption algorithms are supported.
	/// </summary>
	public IEnumerable<string> EncryptionMethodsSupported => innerValidator.EncryptionMethodsSupported;

	/// <summary>
	/// Validates a JSON Web Token (JWT) and checks its revocation status.
	/// </summary>
	/// <param name="jwt">The JWT to be validated.</param>
	/// <param name="parameters">Validation parameters to use during validation.</param>
	/// <returns>
	/// A Result containing either a validated JsonWebToken or a JwtValidationError.
	/// If the token is revoked or already used, it returns a JwtValidationError.
	/// Otherwise, it returns the result from the inner validator.
	/// </returns>
	public async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
		string jwt,
		ValidationParameters parameters)
	{
		var result = await innerValidator.ValidateAsync(jwt, parameters);

		if (!result.TryGetSuccess(out var token))
			return result;

		// Checked before the per-token arms below, and outside them: a cutoff is a fact about the principal
		// rather than about one token, so it must also refuse a token that carries no identifier of its own.
		if (await IsRevokedByCutoffAsync(token.Payload))
			return new JwtValidationError(
				JwtError.TokenRevoked, "Tokens issued to this principal before the revocation cutoff are rejected");

		if (token.Payload.JwtId is { } jwtId)
		{
			// Refresh tokens carry a grant id (Payload.GrantId); other token types leave it null, so the family
			// logic below is inert for them. A revoked grant is a kill switch that outlives any single token:
			// once one member's replay trips it, every member of the family - including the currently active
			// one - is rejected here on its next use (RFC 9700 §4.14.2).
			var grantId = token.Payload.GrantId;

			if (grantId is not null && await tokenRegistry.GetStatusAsync(grantId) == JsonWebTokenStatus.Revoked)
				return new JwtValidationError(JwtError.TokenRevoked, "Refresh token family was revoked");

			switch (await tokenRegistry.GetStatusAsync(jwtId))
			{
				case JsonWebTokenStatus.Used:
					// Replay of a superseded (rotated) token. We cannot tell an attacker from a lagging client,
					// so revoke the whole grant family; the active token dies with it on its next use.
					if (grantId is not null && token.Payload.ExpiresAt is { } grantExpiresAt)
						await tokenRegistry.SetStatusAsync(grantId, JsonWebTokenStatus.Revoked, grantExpiresAt);

					return new JwtValidationError(JwtError.TokenAlreadyUsed, "Token was already used");

				case JsonWebTokenStatus.Revoked:
					return new JwtValidationError(JwtError.TokenRevoked, "Token was revoked");
			}
		}

		return result;
	}

	/// <summary>
	/// Whether a cutoff recorded against this token's subject or session predates the token.
	/// </summary>
	/// <remarks>
	/// Measured against <c>iat</c> rather than <c>auth_time</c>. OpenID Connect Core 1.0 section 2 makes
	/// <c>auth_time</c> REQUIRED only when <c>max_age</c> is requested or when it is asked for as an essential
	/// claim, and OPTIONAL otherwise - so a check built on it would pass silently for most tokens, which is
	/// worse than no check. Every token carries <c>iat</c>.
	/// <para>
	/// A token issued exactly at the cutoff survives, because the cutoff means "everything from before this
	/// moment": the write and the tokens it is meant to kill are ordered by the store, not by this comparison.
	/// </para>
	/// </remarks>
	private async Task<bool> IsRevokedByCutoffAsync(JsonWebTokenPayload payload)
	{
		if (payload.IssuedAt is not { } issuedAt)
			return false;

		return await IsBeforeCutoffAsync(RevocationScope.Subject, payload.Subject, issuedAt)
			|| await IsBeforeCutoffAsync(RevocationScope.Session, payload.SessionId, issuedAt);
	}

	private async Task<bool> IsBeforeCutoffAsync(RevocationScope scope, string? principal, DateTimeOffset issuedAt)
	{
		if (principal is not { Length: > 0 })
			return false;

		return await cutoffRegistry.GetCutoffAsync(scope, principal) is { } cutoff && issuedAt < cutoff;
	}
}
