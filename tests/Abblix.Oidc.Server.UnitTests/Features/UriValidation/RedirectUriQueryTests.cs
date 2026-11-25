// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Reflection;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UriValidation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UriValidation;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 2.3: "The query string component MUST NOT include any parameters
/// defined for use in the authorization response".
/// </summary>
public class RedirectUriQueryTests
{
    /// <summary>
    /// The parameters the rule refuses are those the server puts in an authorization response, every one of them: a
    /// parameter the response model gains is refused in a redirect URI without a second list to keep in step.
    /// </summary>
    [Fact]
    public void TheRefusedParameters_AreTheOnesAnAuthorizationResponseCarries()
    {
        var emitted = typeof(AuthorizationResponse.Parameters)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral)
            .Select(field => (string)field.GetRawConstantValue()!)
            .Order(StringComparer.Ordinal);

        Assert.Equal(emitted, RedirectUriQuery.ResponseParameters.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("https://client.example.com/cb?code=1", "code")]
    [InlineData("https://client.example.com/cb?tenant=a&state", "state")]
    [InlineData("https://client.example.com/cb?a=1&iss=x", "iss")]
    [InlineData("https://client.example.com/cb?err%6Fr=x", "error")]
    [InlineData("https://client.example.com/cb?id_token=", "id_token")]
    [InlineData("com.example.app:/cb?response=x", "response")]
    public void AQueryNamingAResponseParameter_IsFound(string uri, string expected)
    {
        Assert.Equal(expected, RedirectUriQuery.ResponseParameterIn(new Uri(uri)));
    }

    [Theory]
    [InlineData("https://client.example.com/cb")]
    [InlineData("https://client.example.com/cb?")]
    [InlineData("https://client.example.com/cb?tenant=code&codes=1")]
    [InlineData("https://client.example.com/cb?Code=1")]
    [InlineData("https://client.example.com/code?x=state")]
    public void AQueryNamingNoResponseParameter_IsNotFound(string uri)
    {
        Assert.Null(RedirectUriQuery.ResponseParameterIn(new Uri(uri)));
    }
}
