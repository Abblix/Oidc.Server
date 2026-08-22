// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
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
/// <param name="clientInfoProvider">Resolves the client a token names, so a pairwise pseudonym can be
/// opened back into the subject a host would revoke.</param>
/// <param name="subjectTypeConverter">Opens that pseudonym.</param>
/// <param name="innerValidator">The inner validator for initial token validation.</param>
public class TokenStatusValidatorDecorator(
	ITokenRegistry tokenRegistry,
	IRevocationCutoffRegistry cutoffRegistry,
	IClientInfoProvider clientInfoProvider,
	ISubjectTypeConverter subjectTypeConverter,
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
		//
		// Only where the caller validates lifetime, which is the same discriminator and not a coincidence: a
		// cutoff says a token is too old to act on, so a caller that has switched lifetime off is saying it
		// reads this token as a reference to something past rather than as authority. The logout endpoint is
		// exactly that - an id_token_hint names the session that just ended, and refusing it because that
		// session was revoked would break the second logout of a session the first one revoked.
		if (parameters.Options.HasFlag(ValidationOptions.ValidateLifetime)
			&& await IsRevokedByCutoffAsync(token.Payload))
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
	/// Measured against <c>iat</c> rather than <c>auth_time</c>. Both are OPTIONAL in general - RFC 7519
	/// Section 4.1.6 and Section 4.1.7 say so of every registered claim - but this server issues <c>iat</c> on
	/// every token it mints, while <c>auth_time</c> is REQUIRED only when <c>max_age</c> was requested or it
	/// was asked for as an essential claim (OpenID Connect Core 1.0 Section 2). A check built on the second
	/// would pass silently for most tokens, which is worse than no check. A token arriving without <c>iat</c>
	/// is left alone: there is nothing to measure, and refusing it would revoke on the strength of a claim
	/// that was never there.
	/// <para>
	/// A pairwise client's token carries a per-sector pseudonym rather than the subject the host revoked, so
	/// the pseudonym is opened first. Without that, a subject revocation reaches every public client and
	/// silently misses every pairwise one - which is the worst shape a security control can have, because the
	/// deployment that needs it most is the one it fails.
	/// </para>
	/// <para>
	/// The comparison is against the whole second the token declares. A JWT's <c>iat</c> is a whole number of
	/// seconds, so a token minted in the same second as a revocation reads as older than it and is refused.
	/// That errs towards refusing a token the revocation did not mean to catch, which is the direction to err
	/// in, and it bounds the effect at one second.
	/// </para>
	/// </remarks>
	private async Task<bool> IsRevokedByCutoffAsync(JsonWebTokenPayload payload)
	{
		if (payload.IssuedAt is not { } issuedAt)
			return false;

		return await IsBeforeCutoffAsync(RevocationScope.Session, payload.SessionId, issuedAt)
			|| await IsBeforeCutoffAsync(RevocationScope.Subject, await RealSubjectOfAsync(payload), issuedAt);
	}

	/// <summary>
	/// The subject a host would name when revoking, recovered from what the token carries.
	/// </summary>
	/// <remarks>
	/// A public client's token already carries it. A pairwise client's carries a pseudonym sealed to that
	/// client's sector, which only the client's own registration can open - hence the lookup, keyed by the
	/// <c>client_id</c> the token names. When the client cannot be found or its pseudonym cannot be opened,
	/// the raw value is used: a cutoff recorded against it still refuses the token, which is the safe
	/// direction for a value this method could not interpret.
	/// </remarks>
	private async Task<string?> RealSubjectOfAsync(JsonWebTokenPayload payload)
	{
		if (payload.Subject is not { Length: > 0 } subject || payload.ClientId is not { Length: > 0 } clientId)
			return payload.Subject;

		var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId);
		if (clientInfo is null || clientInfo.SubjectType != SubjectTypes.Pairwise)
			return subject;

		return subjectTypeConverter.ConvertBack(subject, clientInfo) ?? subject;
	}

	private async Task<bool> IsBeforeCutoffAsync(RevocationScope scope, string? principal, DateTimeOffset issuedAt)
	{
		if (principal is not { Length: > 0 })
			return false;

		return await cutoffRegistry.GetCutoffAsync(scope, principal) is { } cutoff && issuedAt < cutoff;
	}
}
