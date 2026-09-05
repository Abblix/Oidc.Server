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
/// Adds revocation checking to an existing <see cref="IJsonWebTokenValidator"/>: a token that has been
/// rotated, whose grant family was killed, or that a subject- or session-level cutoff reaches is refused
/// after the inner validator has accepted it.
/// </summary>
/// <remarks>
/// The two halves come from different stores and answer different questions, which is why the cutoff lives
/// behind <see cref="IRevocationCutoffChecker"/> rather than here: this type asks what is recorded about one
/// token, and that one asks what is recorded about the principal behind it.
/// </remarks>
/// <param name="tokenRegistry">The token registry used to check token status.</param>
/// <param name="cutoffChecker">Decides whether a revocation cutoff reaches this token.</param>
/// <param name="innerValidator">The inner validator for initial token validation.</param>
public class TokenStatusValidatorDecorator(
	ITokenRegistry tokenRegistry,
	IRevocationCutoffChecker cutoffChecker,
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
		// rather than about one token, so it must also refuse a token that carries no identifier of its
		// own. Those arms are all guarded by jti, which RFC 7519 Section 4.1.7 makes OPTIONAL. Access
		// tokens do carry one - RFC 9068 Section 2.2 makes it REQUIRED for the at+jwt profile they use -
		// so the tokens this placement actually protects are the rest of what this server mints.
		//
		// Only where the caller validates lifetime, which is the same discriminator and not a coincidence: a
		// cutoff says a token is too old to act on, so a caller that has switched lifetime off is saying it
		// reads this token as a reference to something past rather than as authority. The logout endpoint is
		// exactly that - an id_token_hint names the session that just ended, and refusing it because that
		// session was revoked would break the second logout of a session the first one revoked.
		if (parameters.Options.HasFlag(ValidationOptions.ValidateLifetime)
			&& await cutoffChecker.CheckAsync(token.Payload) is { } cutoffError)
			return cutoffError;

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

				case JsonWebTokenStatus.Unknown:
					// Nothing is recorded about this token, which is what an ordinary one looks like: the
					// registry holds an entry only once a token has been rotated or revoked. Spelled out
					// rather than left to fall through, because acceptance is the outcome here and a status
					// added later must not inherit it silently. TokenStatusCoverageTests walks the enum and
					// fails when one does.
					break;
			}
		}

		return result;
	}
}
