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

using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Requires the "jti" claim to be a non-empty string: "This claim is REQUIRED"
/// (RFC 8417 Section 2.2). The identifier is what every receiver-side replay accounting keys
/// on, so a SET without a usable one is rejected here rather than reaching a consumer that
/// cannot track it.
/// </summary>
public sealed class JwtIdPresenceStep : ISecurityCriticalValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var description = context.UnverifiedPayload!.Json[IanaClaimTypes.Jti] switch
        {
            null => $"The claims carry no '{IanaClaimTypes.Jti}' member (RFC 8417 Section 2.2).",
            JsonValue value when value.TryGetValue<string>(out var jwtId) && jwtId.Length > 0 => null,
            _ => $"The '{IanaClaimTypes.Jti}' claim is not a non-empty string "
                + "(RFC 8417 Section 2.2).",
        };

        var error = description is null
            ? null
            : new SecurityEventTokenValidationError(SecurityEventTokenErrorCode.MalformedToken, description);

        return ValueTask.FromResult(error);
    }
}
