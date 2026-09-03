// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Syntactic validator for the RFC 9449 section 10 <c>dpop_jkt</c> authorization-request
/// parameter: surfaces malformed thumbprints at the authorize / PAR endpoint with
/// <c>invalid_request</c> instead of letting them slip through to /token where they
/// would surface only as <c>invalid_dpop_proof</c> on the live-proof comparison -
/// fail-fast at the binding-time endpoint.
/// </summary>
/// <remarks>
/// Accepts exactly 43 base64url characters (no padding) - the unique encoded length
/// of an RFC 7638 SHA-256 JWK thumbprint, the only digest algorithm DPoP uses
/// (RFC 9449 section 6.1). Rejects any other length or non-base64url character.
/// The parameter is optional; missing values pass through (clients that do not
/// pre-bind don't pay the cost). The actual thumbprint comparison against a
/// presented proof happens at the token endpoint inside
/// <c>DPoPTokenEndpointValidator</c>; this step only enforces wire-format validity.
/// </remarks>
public class ProofKeyThumbprintValidator : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Length in base64url characters of an RFC 7638 SHA-256 JWK Thumbprint
    /// (32 bytes → ceil(32 × 4 / 3) = 43 chars without padding).
    /// </summary>
    private const int Sha256ThumbprintLength = 43;

    /// <inheritdoc/>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var thumbprint = context.Request.ProofKeyThumbprint;
        if (thumbprint is null)
            return null;

        if (thumbprint.Length != Sha256ThumbprintLength || !IsBase64UrlAlphabet(thumbprint))
        {
            return context.InvalidRequest(
                "dpop_jkt is not a valid base64url-encoded RFC 7638 JWK thumbprint.");
        }

        return null;
    }

    private static bool IsBase64UrlAlphabet(string value)
        => value.All(ch => ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_');
}
