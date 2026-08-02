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
/// Requires the "events" claim to be a JSON object holding at least one statement: "The 'events'
/// claim value MUST be a JSON object that contains at least one member" (RFC 8417 Section 2).
/// A JWT without it is not a SET at all - which doubles as the confusion detector RFC 8417
/// Section 4.3 recommends, "reject JWTs containing an 'events' claim unless the JWT is intended
/// to be a SET" read from the receiving side.
/// </summary>
public sealed class EventsPresenceStep : ISecurityEventTokenValidationStep
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
