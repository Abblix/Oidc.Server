// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// Binds the delivered parameters into an <see cref="AuthorizationResponse"/> without judging it.
/// </summary>
internal sealed class AuthorizationResponseParser : IAuthorizationResponseParser
{
    public AuthorizationResponse Parse(IReadOnlyDictionary<string, IReadOnlyList<string>> parameters)
    {
        // Every parameter becomes one JSON property, and System.Text.Json maps them onto the model by the
        // [JsonPropertyName] each property carries. Binding by name rather than reading values out one at a
        // time means a parameter is declared once, on the model, instead of in a reader that can drift from
        // it - the same shape the server binds its own wire models with.
        var properties = new JsonObject();

        foreach (var (name, values) in parameters)
        {
            // An unknown parameter is bound to nothing and ignored, which section 4.1.2 asks for in as many
            // words: "The client MUST ignore unrecognized response parameters." Extensions add parameters,
            // and a client that fails on the ones it does not know breaks against a conformant provider.
            properties[name] = Single(name, values);
        }

        return properties.Deserialize<AuthorizationResponse>()
               ?? throw new AuthorizationResponseException(
                   "The authorization response could not be read as a response at all.");
    }

    /// <summary>
    /// Returns the one value that arrived under <paramref name="name"/>, and refuses a name that arrived
    /// more than once.
    /// </summary>
    /// <remarks>
    /// RFC 6749 section 3.1 forbids the repetition outright, in a sentence that covers this direction
    /// too: "Request and response parameters MUST NOT be included more than once." Refusing rather than
    /// choosing matters because the choice is exactly what an attacker would be making: a callback
    /// carrying two codes lets whichever of them a later reader picks differ from the one these checks
    /// were run against.
    /// </remarks>
    private static string? Single(string name, IReadOnlyList<string> values)
    {
        if (values.Count == 0)
            return null;

        if (values.Count > 1)
        {
            throw new AuthorizationResponseException(
                $"The authorization response carries the '{name}' parameter {values.Count} times, and "
                + "RFC 6749 section 3.1 allows it once. Which of them is meant cannot be guessed at.");
        }

        return values[0];
    }
}
