// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
