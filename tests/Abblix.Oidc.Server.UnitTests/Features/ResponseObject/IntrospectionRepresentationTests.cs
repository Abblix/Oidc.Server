// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ResponseObject;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResponseObject;

/// <summary>
/// The representation an <c>Accept</c> header selects for an introspection response: the JWT where it is named with a
/// weight no lower than JSON's (RFC 9110 section 12.4.2), and whether JSON remains acceptable for the case the JWT
/// cannot be produced.
/// </summary>
public class IntrospectionRepresentationTests
{
    private const string Jwt = MediaTypes.TokenIntrospectionJwt;
    private const string Json = System.Net.Mime.MediaTypeNames.Application.Json;
    private const string AnyApplicationType = "application/*";
    private const string AnyType = "*/*";

    /// <summary>
    /// Each row is one Accept header, its media types separated by commas and a weight after a semicolon.
    /// </summary>
    [Theory]
    [InlineData("", false, true)]
    [InlineData(Jwt, true, false)]
    [InlineData(Json, false, true)]
    [InlineData(Jwt + ", " + Json, true, true)]
    [InlineData(Json + ";1, " + Jwt + ";0.1", false, true)]
    [InlineData(Jwt + ";1, " + Json + ";0.5", true, true)]
    [InlineData(Jwt + ";0.5, " + Json + ";0.5", true, true)]
    [InlineData(Jwt + ";0, " + Json, false, true)]
    [InlineData(Jwt + ";0", false, false)]
    [InlineData(Jwt + ", " + AnyType + ";0.5", true, true)]
    [InlineData(Jwt + ";0.4, " + AnyApplicationType + ";0.5", false, true)]
    [InlineData("text/html", false, false)]
    // RFC 9110 section 12.5.1: the most specific range matching a type gives its weight, so an explicit zero for JSON
    // is not lifted by a wildcard, and a wildcard does not outweigh JSON's own lower weight
    [InlineData(Jwt + ", " + Json + ";0, " + AnyType + ";0.1", true, false)]
    [InlineData(Jwt + ";0.5, " + Json + ";0.2, " + AnyType, true, true)]
    [InlineData(Jwt + ";0.5, " + AnyApplicationType + ";0, " + AnyType, true, false)]
    [InlineData(Jwt + ";0.5, " + AnyApplicationType + ";0.6, " + AnyType + ";0.1", false, true)]
    public void Negotiate_SelectsByWeight(string accept, bool jwt, bool jsonAcceptable)
    {
        var accepted = accept
            .Split(',', System.StringSplitOptions.RemoveEmptyEntries | System.StringSplitOptions.TrimEntries)
            .Select(entry => entry.Split(';'))
            .Select(parts => (parts[0], parts.Length > 1 ? double.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) : (double?)null))
            .ToArray();

        Assert.Equal(new IntrospectionRepresentation(jwt, jsonAcceptable), IntrospectionRepresentation.Negotiate(accepted));
    }
}
