// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
public sealed class PayloadDeserializationStep(EventTypeRegistry registry) : ISecurityEventTokenValidator
{
    /// <inheritdoc />
    public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
        SecurityEventTokenValidationContext context,
        CancellationToken cancellationToken)
    {
        context.Require(
            SecurityEventTokenValidationStates.SignatureVerified | SecurityEventTokenValidationStates.EventsPresent);

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
            context.Establish(SecurityEventTokenValidationStates.PayloadsDeserialized);
        }

        return ValueTask.FromResult(error);
    }
}
