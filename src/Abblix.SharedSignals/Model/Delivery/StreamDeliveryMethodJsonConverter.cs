// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model.Delivery;

/// <summary>
/// Serialization of the polymorphic delivery object, dispatching on the "method" member
/// (SSF 1.0 Section 6.1). An unknown method URI is rejected: a stream whose delivery method this
/// side cannot operate is a configuration to refuse, not to carry around half-parsed.
/// </summary>
public sealed class StreamDeliveryMethodJsonConverter : JsonConverter<StreamDeliveryMethod>
{
    /// <summary>
    /// Handles exactly the abstract base. The concrete types serialize through their ordinary
    /// contracts; matching them here would re-enter this converter without end.
    /// </summary>
    /// <param name="typeToConvert">The type the serializer asks about.</param>
    public override bool CanConvert(Type typeToConvert) => typeToConvert == typeof(StreamDeliveryMethod);

    /// <inheritdoc />
    public override StreamDeliveryMethod? Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        var node = JsonNode.Parse(ref reader);
        if (node is not JsonObject document)
        {
            throw new JsonException("A delivery object must be a JSON object (SSF 1.0 Section 6.1).");
        }

        var method = document[StreamDeliveryMethod.ParameterNames.Method] switch
        {
            null => throw new JsonException(
                $"A delivery object carries no '{StreamDeliveryMethod.ParameterNames.Method}' member "
                + "(SSF 1.0 Section 6.1)."),
            JsonValue value when value.TryGetValue<string>(out var name) => name,
            _ => throw new JsonException(
                $"The '{StreamDeliveryMethod.ParameterNames.Method}' member of a delivery object must "
                + "be a string (SSF 1.0 Section 6.1)."),
        };

        try
        {
            return method switch
            {
                PushDeliveryMethod.MethodUri => document.Deserialize<PushDeliveryMethod>(options),
                PollDeliveryMethod.MethodUri => document.Deserialize<PollDeliveryMethod>(options),
                _ => throw new JsonException($"The delivery method '{method}' is not supported."),
            };
        }
        catch (ArgumentException exception)
        {
            // The subtype constructors enforce the member rules; here their verdict is only
            // re-labelled for the wire, where "this document is invalid" is a JsonException by
            // the serializer's own convention - so a transmitter mapping parse failures to a
            // 400 answers 400, never 500, whatever the malformation.
            throw new JsonException(exception.Message, exception);
        }
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, StreamDeliveryMethod value, JsonSerializerOptions options)
        => JsonSerializer.Serialize<object>(writer, value, options);
}
