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
	/// Time window applied to accommodate clock discrepancies when validating timestamps.
	/// </summary>
	public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

	/// <summary>
	/// Token-type values (per RFC 7515 §4.1.9 <c>typ</c> header) that the JWT MUST match.
	/// When non-null and non-empty the validator pins <c>typ</c> per RFC 8725 §3.11 to
	/// prevent token-class confusion: a JWS signed for one class (id_token, logout_token,
	/// request_object, DPoP proof, JARM response, OAuth access_token) cannot be replayed
	/// as another by relying parties that trust the same issuer for several classes.
	/// </summary>
	/// <remarks>
	/// Matching is case-insensitive and accepts either spelling of the <c>application/</c>
	/// prefix on either side, so <c>at+jwt</c> and <c>application/AT+JWT</c> name the same
	/// class. A <c>typ</c> is a media type, and RFC 7515 §4.1.9 adopts RFC 2045 §5.1 for it:
	/// "Matching of media type and subtype is ALWAYS case-insensitive". The general
	/// string-comparison rules of RFC 7515 §5.3 do not govern this parameter; that section
	/// ends by exempting it by name.
	/// The comparer carried by the set is NOT what produces this behaviour and is not consulted
	/// for matching - the validator compares explicitly, so that its rules cannot be widened or
	/// narrowed by how a host happened to construct the collection. Supply any comparer, or none.
	/// When this property is null or empty the validator skips the check, preserving
	/// historical behaviour for callers that have not opted in.
	/// </remarks>
	public IReadOnlySet<string>? ExpectedTokenTypes { get; init; }

	/// <summary>
	/// JWS signing algorithms (per RFC 7518) that the validator MUST accept; any other
	/// <c>alg</c> in the JOSE header causes rejection. When <c>null</c> or empty the
	/// check is skipped — the validator only enforces the basic
	/// <see cref="ValidationOptions.RequireSignedTokens"/> rule (which forbids
	/// <c>none</c>) and lets any registered signer match.
	/// </summary>
	/// <remarks>
	/// Use this to express policy beyond "signed-or-not" without writing per-algorithm
	/// matchers in callers: pass the asymmetric-only set to enforce DPoP RFC 9449 §4.2,
	/// pass {RS256, ES256} to require small-footprint algorithms only, and so on.
	/// Comparison is byte-exact per RFC 7515 §5.3.
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
