// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

public class ParametersProviderTests
{
    private readonly ParametersProvider _provider = new();

    // Regression: an authorization response carrying expires_in (any response_type that delivers an access token
    // from the authorization endpoint) serializes expires_in as a JSON number. GetParameters must render that
    // numeric value rather than throw. The earlier implementation called JsonElement.GetString() on every property
    // and raised InvalidOperationException on the numeric element, turning every implicit/hybrid token response into
    // an HTTP 500.
    [Fact]
    public void GetParameters_RendersNumericExpiresIn()
    {
        var response = new AuthorizationResponse { ExpiresIn = TimeSpan.FromSeconds(3600) };

        var parameters = _provider.GetParameters(response);

        Assert.Contains(("expires_in", "3600"), parameters);
    }

    // Every JSON value kind maps to its wire form: strings keep their value, numbers and booleans render via their
    // raw JSON text, and JSON nulls become a null value that downstream query/fragment/form encoders drop.
    [Fact]
    public void GetParameters_RendersEachValueKind()
    {
        var parameters = _provider.GetParameters(new
        {
            text = "hello",
            number = 42,
            flag = true,
            missing = (string?)null,
        }).ToArray();

        Assert.Contains(("text", "hello"), parameters);
        Assert.Contains(("number", "42"), parameters);
        Assert.Contains(("flag", "true"), parameters);
        Assert.Contains(("missing", (string?)null), parameters);
    }
}
