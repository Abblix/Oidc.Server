// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Defines parameters used during the validation of a JSON Web Token (JWT).
/// </summary>
public record ValidationParameters
{
	/// <summary>
	/// Options that control various aspects of JWT validation.
	/// </summary>
	public ValidationOptions Options { get; init; } = ValidationOptions.Default;

	/// <summary>
	/// Delegate used to verify the validity of a token issuer.
	/// </summary>
	public ValidateIssuersDelegate? ValidateIssuer { get; set; }

	/// <summary>
	/// Delegate used to validate one or more token audiences.
	/// </summary>
	public ValidateAudienceDelegate? ValidateAudience { get; set; }

	/// <summary>
	/// Delegate that resolves the signing keys for a given issuer, used during token signature validation.
	/// </summary>
	public ResolveIssuerSigningKeysDelegate? ResolveIssuerSigningKeys { get; set; }

	/// <summary>
	/// Delegate that resolves decryption keys for a given issuer, used during token decryption.
	/// </summary>
	public ResolveTokenDecryptionKeysDelegate? ResolveTokenDecryptionKeys { get; set; }

	/// <summary>
	/// How far this token's timestamps may sit either side of this clock and still be honoured.
	/// None unless the caller says otherwise.
	/// </summary>
	public ClockSkew ClockSkew { get; set; } = ClockSkew.None;

	/// <summary>
	/// Which <c>typ</c> header values the token may carry, RFC 8725 section 3.11.
	/// </summary>
	/// <remarks>
	/// Required: every validation states the types it accepts, or states that its caller judges the type, as
	/// <see cref="TokenTypePolicy"/> explains.
	/// </remarks>
	public required TokenTypePolicy TokenTypes { get; init; }

	/// <summary>
	/// JWS signing algorithms (per RFC 7518) that the validator MUST accept; any other
	/// <c>alg</c> in the JOSE header causes rejection. When <c>null</c> or empty the
	/// check is skipped - the validator only enforces the basic
	/// <see cref="ValidationOptions.RequireSignedTokens"/> rule (which forbids
	/// <c>none</c>) and lets any registered signer match.
	/// </summary>
	/// <remarks>
	/// Use this to express policy beyond "signed-or-not" without writing per-algorithm
	/// matchers in callers: pass the asymmetric-only set to enforce DPoP RFC 9449 section 4.2,
	/// pass {RS256, ES256} to require small-footprint algorithms only, and so on.
	/// Comparison is byte-exact per RFC 7515 section 5.3.
	/// </remarks>
	public IReadOnlySet<string>? AllowedSigningAlgorithms { get; init; }

	/// <summary>
	/// Resolves signing keys (JWKs) asynchronously for a specified issuer.
	/// </summary>
	/// <param name="issuer">Issuer whose signing keys are to be resolved.</param>
	/// <returns>An asynchronous stream of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveIssuerSigningKeysDelegate(string issuer);

	/// <summary>
	/// Resolves decryption keys (JWKs) asynchronously for a specified issuer.
	/// </summary>
	/// <param name="issuer">Issuer whose decryption keys are to be resolved.</param>
	/// <returns>An asynchronous stream of JSON Web Keys.</returns>
	public delegate IAsyncEnumerable<JsonWebKey> ResolveTokenDecryptionKeysDelegate(string issuer);

	/// <summary>
	/// Validates a collection of audiences against expected values.
	/// </summary>
	/// <param name="audiences">Audiences to be validated.</param>
	/// <returns>A task that returns true if validation succeeds.</returns>
	public delegate Task<bool> ValidateAudienceDelegate(IEnumerable<string> audiences);

	/// <summary>
	/// Validates a token issuer against expected values.
	/// </summary>
	/// <param name="issuer">Issuer to be validated.</param>
	/// <returns>A task that returns true if validation succeeds.</returns>
	public delegate Task<bool> ValidateIssuersDelegate(string issuer);
};
