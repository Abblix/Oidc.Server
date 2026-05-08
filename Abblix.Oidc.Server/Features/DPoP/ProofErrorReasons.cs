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
    public const string InvalidTyp = "invalid_typ";

    /// <summary>Header <c>alg</c> is missing, not asymmetric, or not in the configured whitelist.</summary>
    public const string InvalidAlg = "invalid_alg";

    /// <summary>Header <c>jwk</c> is required but missing.</summary>
    public const string MissingJwk = "missing_jwk";

    /// <summary>Header <c>jwk</c> is malformed or contains private-key material.</summary>
    public const string InvalidJwk = "invalid_jwk";

    /// <summary>JWS signature does not verify under the embedded <c>jwk</c>.</summary>
    public const string SignatureInvalid = "signature_invalid";

    /// <summary>Payload <c>htm</c> does not match the request method.</summary>
    public const string HtmMismatch = "htm_mismatch";

    /// <summary>Payload <c>htu</c> claim is missing.</summary>
    public const string HtuMissing = "htu_missing";

    /// <summary>Payload <c>htu</c> is not a valid absolute URI.</summary>
    public const string HtuInvalid = "htu_invalid";

    /// <summary>Payload <c>htu</c> does not match the request URI after RFC 3986 §6.2 canonicalisation.</summary>
    public const string HtuMismatch = "htu_mismatch";

    /// <summary>Payload <c>iat</c> claim is missing.</summary>
    public const string IatMissing = "iat_missing";

    /// <summary>Payload <c>iat</c> is not a Unix-time numeric.</summary>
    public const string IatInvalid = "iat_invalid";

    /// <summary>Payload <c>iat</c> falls outside the configured tolerance window around the current time.</summary>
    public const string IatOutOfWindow = "iat_out_of_window";

    /// <summary>Payload <c>ath</c> claim is required (an access token is presented) but missing.</summary>
    public const string AthMissing = "ath_missing";

    /// <summary>Payload <c>ath</c> does not match <c>Base64Url(SHA-256(access_token))</c>.</summary>
    public const string AthMismatch = "ath_mismatch";

    /// <summary>Payload <c>jti</c> claim is missing.</summary>
    public const string JtiMissing = "jti_missing";

    /// <summary>Payload <c>jti</c> has already been used within the acceptance window.</summary>
    public const string ReplayDetected = "replay_detected";
}
