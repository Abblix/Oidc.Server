// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Takes the compact serialization apart and parses its header and claims, WITHOUT trusting
/// either: parsing establishes shape, and everything read here stays in the context's unverified
/// half until the signature step speaks.
/// </summary>
/// <remarks>
/// Parsing before signature verification is what lets the cheap rejections - wrong type, wrong
/// issuer, present "exp" - run before any cryptography, and it is safe exactly because nothing
/// acts on the parsed values beyond rejecting the token. Encrypted SETs are not supported by this
/// version: none of the first consumers encrypts, and JWS-only keeps the parse step free of key
/// material. A five-segment token reports that plainly rather than as a generic parse failure.
/// </remarks>
public sealed class ParseStep : ISecurityEventTokenValidator
{
    private const int JwsSegmentCount = 3;
    private const int JweSegmentCount = 5;

    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        var segments = context.CompactToken.Split('.');

        switch (segments.Length)
        {
            case JwsSegmentCount:
                break;

            case JweSegmentCount:
                return ValueTask.FromResult<SecurityEventTokenValidationError?>(
                    new SecurityEventTokenValidationError(
                        SecurityEventTokenErrorCode.DecryptionFailed,
                        "The token is JWE-encrypted, which this validation profile does not support."));

            default:
                return ValueTask.FromResult<SecurityEventTokenValidationError?>(
                    new SecurityEventTokenValidationError(
                        SecurityEventTokenErrorCode.MalformedToken,
                        $"A compact JWS has {JwsSegmentCount} segments; this token has {segments.Length}."));
        }

        // Read as the JWT core reads a compact JWS, so a part carrying padding or whitespace, a header or claims set
        // that is not UTF-8 JSON, or one repeating a member name is malformed here as it is there
        var parsed = JwsCompactParser.Parse(segments);
        if (parsed.TryGetFailure(out var failure))
        {
            return ValueTask.FromResult<SecurityEventTokenValidationError?>(
                new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.MalformedToken,
                    failure.ErrorDescription));
        }

        var token = parsed.GetSuccess();
        context.UnverifiedHeader = token.Header;
        context.UnverifiedPayload = token.Payload;
        context.Establish(SecurityEventTokenValidationStates.Parsed);
        return ValueTask.FromResult<SecurityEventTokenValidationError?>(null);
    }
}
