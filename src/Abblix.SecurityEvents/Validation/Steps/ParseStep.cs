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

using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
public sealed class ParseStep : ISecurityEventTokenValidationStep
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

        SecurityEventTokenValidationError? error = null;
        try
        {
            context.UnverifiedHeader = new JsonWebTokenHeader(ParseSegment(segments[0], "header"));
            context.UnverifiedPayload = new JsonWebTokenPayload(ParseSegment(segments[1], "claims"));
            context.Establish(SecurityEventTokenValidationState.Parsed);
        }
        catch (Exception exception) when (exception is FormatException or JsonException)
        {
            error = new SecurityEventTokenValidationError(
                SecurityEventTokenErrorCode.MalformedToken,
                exception.Message);
        }

        return ValueTask.FromResult(error);
    }

    private static JsonObject ParseSegment(string segment, string name)
    {
        var json = Encoding.UTF8.GetString(Base64Url.DecodeFromChars(segment));

        return JsonNode.Parse(json) as JsonObject
            ?? throw new JsonException($"The token's {name} segment is not a JSON object.");
    }
}
