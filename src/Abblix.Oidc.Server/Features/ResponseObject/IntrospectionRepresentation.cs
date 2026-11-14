// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.ResponseObject;

/// <summary>
/// The representation of an introspection response a caller's <c>Accept</c> header asks for (RFC 9110 section 12.5.1),
/// decided once for every host: the JWT of RFC 9701 or the JSON document of RFC 7662.
/// </summary>
/// <param name="Jwt">Whether the JWT is to be served: the caller names it with a weight no lower than JSON's.</param>
/// <param name="JsonAcceptable">Whether the JSON document is acceptable to the caller as well, which is what is served
/// where the JWT cannot be produced, instead of refusing the request.</param>
public readonly record struct IntrospectionRepresentation(bool Jwt, bool JsonAcceptable)
{
    /// <summary>
    /// The representation the media types of an <c>Accept</c> header select.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 12.4.2: the weight is "relative", and "a value of 0 means 'not acceptable'". The JWT is chosen
    /// where it is named (RFC 9701 section 4) and JSON is not weighted higher; at equal weights the JWT wins, being the
    /// one the caller had to name. JSON is acceptable where the header is absent, or gives it a weight above zero. That
    /// weight is the one of the most specific range naming it, RFC 9110 section 12.5.1: "The media type quality factor
    /// associated with a given type is determined by finding the media range with the highest precedence that matches
    /// the type", application/json before application/* before */*, so a zero given JSON itself is not lifted by a
    /// wildcard. Only the JWT media type itself selects the JWT; no range does.
    /// </remarks>
    /// <param name="accepted">Each media type or range of the header with its quality, null where it carries none.</param>
    public static IntrospectionRepresentation Negotiate(IReadOnlyCollection<(string MediaType, double? Quality)> accepted)
    {
        var weighted = accepted.Select(entry => (entry.MediaType, Quality: entry.Quality ?? 1)).ToArray();

        var jwt = Acceptable(WeightOf(weighted, MediaTypes.TokenIntrospectionJwt));
        var json = Acceptable(
            WeightOf(weighted, MediaTypeNames.Application.Json) ??
            WeightOf(weighted, AnyApplicationType) ??
            WeightOf(weighted, AnyType));

        return new IntrospectionRepresentation(
            Jwt: jwt is { } jwtWeight && !(json > jwtWeight),
            JsonAcceptable: accepted.Count == 0 || json is not null);
    }

    /// <summary>
    /// The highest weight the header gives <paramref name="mediaType"/> named exactly, zero included, or null where it
    /// does not name it.
    /// </summary>
    private static double? WeightOf((string MediaType, double Quality)[] weighted, string mediaType)
        => weighted.Where(entry => Is(entry.MediaType, mediaType)).Select(entry => (double?)entry.Quality).Max();

    /// <summary>
    /// The weight where it admits the type, null where it is zero (RFC 9110 section 12.4.2) or absent.
    /// </summary>
    private static double? Acceptable(double? weight) => weight > 0 ? weight : null;

    /// <summary>The media range of RFC 9110 section 12.5.1 covering every application type.</summary>
    private const string AnyApplicationType = "application/*";

    /// <summary>The media range of RFC 9110 section 12.5.1 covering every media type.</summary>
    private const string AnyType = "*/*";

    private static bool Is(string mediaType, string expected)
        => string.Equals(mediaType, expected, StringComparison.OrdinalIgnoreCase);
}
