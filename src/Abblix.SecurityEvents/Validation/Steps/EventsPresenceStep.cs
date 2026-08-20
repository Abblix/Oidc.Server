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
/// Requires the "events" claim to be a JSON object holding at least one statement: "The 'events'
/// claim value MUST be a JSON object that contains at least one member" (RFC 8417 Section 2).
/// A JWT without it is not a SET at all - which doubles as the confusion detector RFC 8417
/// Section 4.3 recommends, "reject JWTs containing an 'events' claim unless the JWT is intended
/// to be a SET" read from the receiving side.
/// </summary>
public sealed class EventsPresenceStep : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(SecurityEventTokenValidationStates.Parsed);

        var description = context.UnverifiedPayload!.Json[JwtClaimTypes.Events] switch
        {
            null => $"The claims carry no '{JwtClaimTypes.Events}' member (RFC 8417 Section 2.2).",
            JsonObject { Count: 0 } =>
                $"The '{JwtClaimTypes.Events}' claim is empty; it must contain at least one member "
                + "(RFC 8417 Section 2).",
            JsonObject => null,
            _ => $"The '{JwtClaimTypes.Events}' claim is not a JSON object (RFC 8417 Section 2.2).",
        };

        SecurityEventTokenValidationError? error;
        if (description is null)
        {
            context.Establish(SecurityEventTokenValidationStates.EventsPresent);
            error = null;
        }
        else
        {
            error = new SecurityEventTokenValidationError(SecurityEventTokenErrorCode.MissingEvents, description);
        }

        return ValueTask.FromResult(error);
    }
}
