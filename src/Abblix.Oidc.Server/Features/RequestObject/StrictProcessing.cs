// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Strict request object processing (RFC 9101 section 6.3), where the object is the whole request: the parameters a
/// request carried outside its object, which it drops, and what the object itself must name.
/// </summary>
internal static class StrictProcessing
{
    /// <summary>
    /// The names of the parameters of <paramref name="request"/> that strict processing drops: each is absent from the
    /// object, is not the parameter that carries the object itself, and differs from the request model's default (so it
    /// was actually supplied).
    /// </summary>
    public static IReadOnlyList<string> IgnoredOutsideParameters<T>(T request, string? requestObject, JsonObject payload)
        where T : class
    {
        var outer = JsonSerializer.SerializeToNode(request)?.AsObject();
        if (outer is null)
            return [];

        var defaults = JsonSerializer.SerializeToNode(Activator.CreateInstance<T>())?.AsObject();

        return outer
            .Where(parameter => !payload.ContainsKey(parameter.Key) &&
                                !CarriesRequestObject(parameter.Value, requestObject) &&
                                !IsLeftAtDefault(parameter.Key, parameter.Value, defaults))
            .Select(parameter => parameter.Key)
            .ToList();
    }

    /// <summary>
    /// Why strict processing refuses the object's claims, or null. The object is the whole request (FAPI 1.0 Part 2
    /// section 5.2.2: the server "shall only use the parameters included in the signed request object"), so an object
    /// naming no scope leaves the request with none, and RFC 6749 section 3.3 lets the server refuse such a request
    /// rather than apply a default value. What is wrong is the object, which RFC 9101 section 7 answers with
    /// invalid_request_object, "The request parameter contains an invalid Request Object". Our choice over the
    /// invalid_scope section 3.3 names for a failed request: the scope is missing from the object rather than wrong.
    /// </summary>
    public static string? WhyRefused(JsonObject payload)
        => NamesNoScope(payload) ? $"The request object must include the {IanaClaimTypes.Scope} parameter" : null;

    /// <summary>
    /// Whether the object carries no scope, or a scope naming no value. A scope of another shape is left to the
    /// binder, which refuses it as a malformed parameter.
    /// </summary>
    private static bool NamesNoScope(JsonObject payload)
        => payload[IanaClaimTypes.Scope] switch
        {
            null => true,
            JsonValue scope when scope.TryGetValue<string>(out var value) => string.IsNullOrWhiteSpace(value),
            _ => false,
        };

    /// <summary>
    /// Whether this outside parameter is the one carrying the request object, which is expected to be outside it.
    /// </summary>
    private static bool CarriesRequestObject(JsonNode? value, string? requestObject)
        => value?.GetValueKind() == JsonValueKind.String && value.GetValue<string>() == requestObject;

    /// <summary>
    /// Whether this outside parameter is left at its type default, so the client did not actually supply it.
    /// </summary>
    private static bool IsLeftAtDefault(string name, JsonNode? value, JsonObject? defaults)
        => JsonNode.DeepEquals(value, defaults?[name]);
}
