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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.Validation.Steps;

/// <summary>
/// Deserializes every event payload through the registry - into its registered model, or the raw
/// passthrough for a type the registry does not know - so the consumer receives typed events
/// instead of repeating this work per statement.
/// </summary>
/// <remarks>
/// The step requires a verified signature: deserialization into registered models is the
/// pipeline's most elaborate parsing, and running it on unverified input would hand an attacker
/// the largest possible parser surface before any authenticity check. The ordering contract makes
/// a pipeline composed that way fail its first run.
/// </remarks>
/// <param name="registry">The event-type registrations of this receiver.</param>
public sealed class PayloadDeserializationStep(EventTypeRegistry registry) : ISecurityEventTokenValidationStep
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(
            SecurityEventTokenValidationState.SignatureVerified | SecurityEventTokenValidationState.EventsPresent);

        var events = context.Token!.Events;
        if (events is null)
        {
            // EventsPresent was established on the parsed bytes and the signature covered the
            // same bytes, so a missing claim here means the pipeline's own state lied - a bug,
            // not a token.
            throw new InvalidOperationException(
                "The validated token carries no events object although the presence step passed.");
        }

        var payloads = new Dictionary<string, IEventPayload>(events.Count, StringComparer.Ordinal);
        SecurityEventTokenValidationError? error = null;

        foreach (var (eventType, payload) in events.Json)
        {
            if (payload is not JsonObject payloadObject)
            {
                error = new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.MalformedToken,
                    $"The payload of event '{eventType}' is not a JSON object (RFC 8417 Section 2.2).");
                break;
            }

            try
            {
                payloads.Add(eventType, registry.Deserialize(eventType, payloadObject));
            }
            catch (JsonException exception)
            {
                error = new SecurityEventTokenValidationError(
                    SecurityEventTokenErrorCode.MalformedToken,
                    $"The payload of event '{eventType}' does not match its registered model: "
                    + exception.Message);
                break;
            }
        }

        if (error is null)
        {
            context.EventPayloads = payloads;
            context.Establish(SecurityEventTokenValidationState.PayloadsDeserialized);
        }

        return ValueTask.FromResult(error);
    }
}
