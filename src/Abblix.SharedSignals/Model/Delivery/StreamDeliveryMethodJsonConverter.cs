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

        var method = document[StreamDeliveryMethod.ParameterNames.Method]?.GetValue<string>();

        return method switch
        {
            PushDeliveryMethod.MethodUri => document.Deserialize<PushDeliveryMethod>(options),
            PollDeliveryMethod.MethodUri => document.Deserialize<PollDeliveryMethod>(options),
            null => throw new JsonException(
                $"A delivery object carries no '{StreamDeliveryMethod.ParameterNames.Method}' member "
                + "(SSF 1.0 Section 6.1)."),
            _ => throw new JsonException($"The delivery method '{method}' is not supported."),
        };
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, StreamDeliveryMethod value, JsonSerializerOptions options)
        => JsonSerializer.Serialize<object>(writer, value, options);
}
