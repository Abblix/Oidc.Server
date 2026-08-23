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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Enhances the functionality of an existing <see cref="IJsonWebTokenValidator"/> by adding token revocation validation capabilities.
/// This decorator checks whether the JSON Web Token (JWT) has been revoked or used before and, if so, invalidates the token.
/// It utilizes an <see cref="ITokenRegistry"/> to check the token's status and an inner <see cref="IJsonWebTokenValidator"/>
/// for initial token validation.
/// </summary>
/// <param name="logger">Records a refusal, so a revoked token is distinguishable from an expired one.</param>
/// <param name="tokenRegistry">The token registry used to check token status.</param>
/// <param name="cutoffRegistry">The registry of subject- and session-level revocation cutoffs.</param>
/// <param name="issuerProvider">Names this server, so a cutoff is only measured against tokens it minted.</param>
/// <param name="options">Carries the tolerance the cutoff comparison allows for clock differences.</param>
/// <param name="clientInfoProvider">Resolves the client a token names, so a pairwise pseudonym can be
/// opened back into the subject a host would revoke.</param>
/// <param name="subjectTypeConverter">Opens that pseudonym.</param>
/// <param name="innerValidator">The inner validator for initial token validation.</param>
public partial class TokenStatusValidatorDecorator(
	ILogger<TokenStatusValidatorDecorator> logger,
	ITokenRegistry tokenRegistry,
	IRevocationCutoffRegistry cutoffRegistry,
	IIssuerProvider issuerProvider,
	IOptions<OidcOptions> options,
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
			&& await RevocationCutoffErrorAsync(token.Payload) is { } cutoffError)
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

	/// <summary>
	/// The refusal a revocation cutoff calls for on this token, or <c>null</c> when no cutoff reaches it.
	/// </summary>
	/// <remarks>
	/// Applies only to tokens this server minted. A cutoff names a principal in this server's own namespace,
	/// while the same validator also sees tokens minted elsewhere - a client's <c>private_key_jwt</c>
	/// assertion (RFC 7523 Section 3, where <c>sub</c> is the <c>client_id</c>), an assertion from a federated
	/// issuer under the jwt-bearer grant, a request object, a software statement. Their subjects are strings
	/// from other namespaces, so matching one against our cutoff refuses a stranger's token for a revocation
	/// that has nothing to do with it - and under <c>client_credentials</c> this server's own <c>sub</c> is a
	/// <c>client_id</c> too, so the two namespaces genuinely collide.
	/// <para>
	/// Measured against <c>iat</c> rather than <c>auth_time</c>. Both are OPTIONAL in general (RFC 7519
	/// Section 4.1.6), but this server issues <c>iat</c> on every token it mints - RFC 9068 Section 2.2 makes
	/// it REQUIRED for the <c>at+jwt</c> profile these access tokens use - while <c>auth_time</c> is REQUIRED
	/// only when <c>max_age</c> was requested or it was asked for as an essential claim (OpenID Connect Core
	/// 1.0 Section 2). A check built on the second would pass silently for most tokens, which is worse than
	/// no check. A token arriving without <c>iat</c> is left alone: there is nothing to measure, and refusing
	/// it would revoke on the strength of a claim that was never there.
	/// </para>
	/// <para>
	/// What this therefore does and does not do: it refuses tokens already issued, and it does not suspend an
	/// account. <c>iat</c> moves forward on every re-authorization, so a browser session this server still
	/// holds can mint a fresh token that passes the cutoff. A deployment suspending an account ends that
	/// session too - <see cref="ITokenRevoker.RevokeSessionAsync"/> alongside whatever ends its own sign-in
	/// state - rather than relying on this alone.
	/// </para>
	/// <para>
	/// The comparison is against the whole second the token declares. A JWT's <c>iat</c> is a whole number of
	/// seconds, so a token minted in the same second as a revocation reads as older than it and is refused.
	/// That errs towards refusing a token the revocation did not mean to catch, which is the direction to err
	/// in. Clock differences between instances run the other way and are not bounded by the token, which is
	/// what <see cref="Common.Configuration.OidcOptions.RevocationCutoffSkew"/> answers.
	/// </para>
	/// </remarks>
	private async Task<JwtValidationError?> RevocationCutoffErrorAsync(JsonWebTokenPayload payload)
	{
		if (payload.IssuedAt is not { } issuedAt || !IsOurOwnToken(payload))
			return null;

		if (await IsBeforeCutoffAsync(RevocationScope.Session, payload.SessionId, issuedAt))
		{
			LogTokenRefusedByCutoff(RevocationScope.Session, issuedAt);
			return RevokedByCutoff;
		}

		var (resolved, subject) = await TryResolveSubjectAsync(payload);
		if (!resolved)
		{
			// The subject could not be recovered, so whether a cutoff covers this token is unknown - and a
			// revocation control that cannot evaluate its input must not answer "not revoked". The sibling
			// call sites of ConvertBack refuse on the same input for the same reason.
			LogSubjectCouldNotBeResolved(payload.ClientId);
			return new JwtValidationError(
				JwtError.TokenRevoked,
				"The subject of this token could not be resolved, so a revocation recorded against it cannot be ruled out");
		}

		if (!await IsBeforeCutoffAsync(RevocationScope.Subject, subject, issuedAt))
			return null;

		LogTokenRefusedByCutoff(RevocationScope.Subject, issuedAt);
		return RevokedByCutoff;
	}

	private static JwtValidationError RevokedByCutoff => new(
		JwtError.TokenRevoked, "Tokens issued to this principal before the revocation cutoff are rejected");

	/// <summary>
	/// Whether this token names this server as its issuer, which is what puts its subject in the namespace a
	/// cutoff is recorded in.
	/// </summary>
	/// <remarks>
	/// A token with no <c>iss</c> is not ours either: everything this server mints carries one, so its absence
	/// says the token came from somewhere that does not follow our conventions.
	/// </remarks>
	private bool IsOurOwnToken(JsonWebTokenPayload payload)
		=> payload.Issuer is { Length: > 0 } issuer && issuer == issuerProvider.GetIssuer();

	/// <summary>
	/// The subject a host would name when revoking, recovered from what the token carries.
	/// </summary>
	/// <remarks>
	/// A public client's token already carries it. A pairwise client's carries a pseudonym sealed to that
	/// client's sector, which only the client's own registration can open - hence the lookup, keyed by the
	/// <c>client_id</c> the token names.
	/// <para>
	/// Answers <c>false</c> when the client is gone or its pseudonym could not be opened, which happens when
	/// the pairwise salt was rotated or the client's sector identifier moved. Falling back to the sealed value
	/// would look safe and is not: nobody records a cutoff against a pseudonym, so the lookup would miss and
	/// every affected token would be accepted - a revocation silently undone for exactly the deployment that
	/// chose the stricter privacy setting.
	/// </para>
	/// </remarks>
	private async Task<(bool Resolved, string? Subject)> TryResolveSubjectAsync(JsonWebTokenPayload payload)
	{
		if (payload.Subject is not { Length: > 0 } subject || payload.ClientId is not { Length: > 0 } clientId)
			return (true, payload.Subject);

		var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId);
		if (clientInfo is null)
			return (false, null);

		if (clientInfo.SubjectType != SubjectTypes.Pairwise)
			return (true, subject);

		try
		{
			// Throws rather than answering null when pairwise identifiers are not configured at all, which a
			// client registered as pairwise can still reach by presenting an assertion it never received a
			// token for. Same unknown, same answer.
			return subjectTypeConverter.ConvertBack(subject, clientInfo) is { } realSubject
				? (true, realSubject)
				: (false, null);
		}
		catch (InvalidOperationException)
		{
			return (false, null);
		}
	}

	private async Task<bool> IsBeforeCutoffAsync(RevocationScope scope, string? principal, DateTimeOffset issuedAt)
	{
		if (principal is not { Length: > 0 })
			return false;

		if (await cutoffRegistry.GetCutoffAsync(scope, principal) is not { } cutoff)
			return false;

		// The tolerance widens what the cutoff catches, because the two instants come from different
		// clocks and only one direction of that error is recoverable.
		return issuedAt < cutoff + options.Value.RevocationCutoffSkew;
	}
}
