// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// The parameters a request carried outside its request object, which strict processing (RFC 9101 section 6.3) drops.
/// </summary>
internal static class IgnoredOutsideParameters
{
    /// <summary>
    /// The names of the parameters of <paramref name="request"/> that strict processing drops: each is absent from the
    /// object, is not the parameter that carries the object itself, and differs from the request model's default (so it
    /// was actually supplied).
    /// </summary>
    public static IReadOnlyList<string> Of<T>(T request, string? requestObject, JsonObject payload)
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
