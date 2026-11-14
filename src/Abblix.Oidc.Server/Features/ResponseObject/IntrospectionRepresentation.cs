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
    /// one the caller had to name. JSON is acceptable where the header is absent, or names it or a range covering it.
    /// </remarks>
    /// <param name="accepted">Each media type or range of the header with its quality, null where it carries none.</param>
    public static IntrospectionRepresentation Negotiate(IReadOnlyCollection<(string MediaType, double? Quality)> accepted)
    {
        var acceptable = accepted
            .Select(entry => (entry.MediaType, Quality: entry.Quality ?? 1))
            .Where(entry => entry.Quality > 0)
            .ToArray();

        var jwt = HighestWeight(acceptable, mediaType => Is(mediaType, MediaTypes.TokenIntrospectionJwt));
        var json = HighestWeight(acceptable, CoversJson);

        return new IntrospectionRepresentation(
            Jwt: jwt is { } jwtWeight && !(json > jwtWeight),
            JsonAcceptable: accepted.Count == 0 || json is not null);
    }

    private static double? HighestWeight((string MediaType, double Quality)[] acceptable, Func<string, bool> matches)
        => acceptable.Where(entry => matches(entry.MediaType)).Select(entry => (double?)entry.Quality).Max();

    private static bool CoversJson(string mediaType)
        => Is(mediaType, MediaTypeNames.Application.Json) || Is(mediaType, AnyApplicationType) || Is(mediaType, AnyType);

    /// <summary>The media range of RFC 9110 section 12.5.1 covering every application type.</summary>
    private const string AnyApplicationType = "application/*";

    /// <summary>The media range of RFC 9110 section 12.5.1 covering every media type.</summary>
    private const string AnyType = "*/*";

    private static bool Is(string mediaType, string expected)
        => string.Equals(mediaType, expected, StringComparison.OrdinalIgnoreCase);
}
