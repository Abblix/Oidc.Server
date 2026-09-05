// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DPoP;

/// <summary>
/// Stable, machine-friendly reason tokens that <see cref="ProofValidator"/> assigns to
/// <see cref="ProofError.Reason"/> for log filters and metric labels. These are the
/// internal fine-grained failure categories; the OAuth-protocol-level error code surfaced
/// to clients is always <c>invalid_dpop_proof</c> (or <c>use_dpop_nonce</c> for the
/// nonce-required path) regardless of which of these matched.
/// </summary>
public static class ProofErrorReasons
{
    /// <summary>JWS compact form is not three dot-separated segments, base64url-decode failed,
    /// or the header/payload is not a JSON object.</summary>
    public const string MalformedJwt = "malformed_jwt";

    /// <summary>Header <c>typ</c> is not <c>dpop+jwt</c>.</summary>
    public const string InvalidTokenType = "invalid_typ";

    /// <summary>Header <c>alg</c> is missing, not asymmetric, or not in the configured whitelist.</summary>
    public const string InvalidAlgorithm = "invalid_alg";

    /// <summary>Header <c>jwk</c> is missing, malformed, or contains private-key material.</summary>
    /// <remarks>
    /// Only where THIS validator establishes it. A refusal that came from the JWT core arrives under
    /// <see cref="InvalidHeader"/> instead, because the core reports a bad <c>jwk</c>, a bad <c>crit</c>
    /// and a missing required header under one category and cannot tell a consumer which it met.
    /// </remarks>
    public const string InvalidJwk = "invalid_jwk";

    /// <summary>A JOSE header parameter is malformed or violates a structural rule.</summary>
    /// <remarks>
    /// Deliberately named for the header rather than for one member of it: this is what the JWT core's
    /// <c>InvalidHeader</c> becomes, and that category covers an unusable <c>jwk</c>, a <c>crit</c> that
    /// is malformed or names an extension nothing handles, and a header a trust model requires and the
    /// token omits. Reporting all three as <c>invalid_jwk</c> told a client its key was bad over a
    /// <c>crit</c> it had written itself.
    /// <para>
    /// WHICH of the three happened is on <see cref="ProofError.Detail"/> and goes no further - no
    /// response, no log, no metric label. That is a decision rather than an omission: two of the core's
    /// <c>crit</c> descriptions are written by quoting the token, so the value carries what the client
    /// put there, and the rest are constants that cannot be told apart from them at this seam.
    /// </para>
    /// <para>
    /// The cost is stated rather than hidden: for all three causes a client is told <c>invalid_header</c>
    /// and an operator's log line says the same, so nothing the library emits separates an unusable
    /// <c>jwk</c> from a bad <c>crit</c>. A host that wants the difference reads
    /// <see cref="ProofError.Detail"/> off its own call - and sanitises it, because it may be the
    /// client's own bytes.
    /// </para>
    /// </remarks>
    public const string InvalidHeader = "invalid_header";

    /// <summary>JWS signature does not verify under the embedded <c>jwk</c>.</summary>
    public const string SignatureInvalid = "signature_invalid";

    /// <summary>Payload <c>htm</c> does not match the request method.</summary>
    public const string HttpMethodMismatch = "htm_mismatch";

    /// <summary>Payload <c>htu</c> claim is missing.</summary>
    public const string HttpUriMissing = "htu_missing";

    /// <summary>Payload <c>htu</c> is not a valid absolute URI.</summary>
    public const string HttpUriInvalid = "htu_invalid";

    /// <summary>Payload <c>htu</c> does not match the request URI after RFC 3986 §6.2 canonicalisation.</summary>
    public const string HttpUriMismatch = "htu_mismatch";

    /// <summary>Payload <c>iat</c> claim is missing.</summary>
    public const string IssuedAtMissing = "iat_missing";

    /// <summary>Payload <c>iat</c> is not a Unix-time numeric.</summary>
    public const string IssuedAtInvalid = "iat_invalid";

    /// <summary>Payload <c>iat</c> falls outside the configured tolerance window around the current time.</summary>
    public const string IssuedAtOutOfWindow = "iat_out_of_window";

    /// <summary>Payload <c>ath</c> claim is required (an access token is presented) but missing.</summary>
    public const string AccessTokenHashMissing = "ath_missing";

    /// <summary>Payload <c>ath</c> does not match <c>Base64Url(SHA-256(access_token))</c>.</summary>
    public const string AccessTokenHashMismatch = "ath_mismatch";

    /// <summary>Payload <c>jti</c> claim is missing.</summary>
    public const string JwtIdMissing = "jti_missing";

    /// <summary>Payload <c>jti</c> has already been used within the acceptance window.</summary>
    public const string ReplayDetected = "replay_detected";
}
