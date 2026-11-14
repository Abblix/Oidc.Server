// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.UserInfo;

/// <summary>
/// The scheme a UserInfo request presented its access token with (RFC 9449 section 7.2), one row per way of sending
/// it: the Authorization header in either scheme, the body and the query (RFC 6750 section 2), and their pairings.
/// </summary>
public class AccessTokenPresentationTests
{
    public enum Parameter { None, Form, Query }

    [Theory]
    [InlineData(TokenTypes.Bearer, Parameter.None, AccessTokenScheme.Bearer)]
    [InlineData(TokenTypes.DPoP, Parameter.None, AccessTokenScheme.DPoP)]
    [InlineData(null, Parameter.Form, AccessTokenScheme.Bearer)]
    [InlineData(null, Parameter.Query, AccessTokenScheme.Bearer)]
    [InlineData(TokenTypes.Bearer, Parameter.Form, AccessTokenScheme.Bearer)]
    [InlineData(TokenTypes.DPoP, Parameter.Form, null)]
    [InlineData(TokenTypes.DPoP, Parameter.Query, null)]
    [InlineData(null, Parameter.None, null)]
    [InlineData(TokenTypes.Basic, Parameter.None, null)]
    public void SchemeOf_NamesTheSchemeTheTokenWasPresentedWith(
        string? headerScheme, Parameter parameter, AccessTokenScheme? expected)
    {
        var request = parameter switch
        {
            Parameter.None => new UserInfoRequest(),
            Parameter.Form => new UserInfoRequest { AccessTokenInForm = "token" },
            Parameter.Query => new UserInfoRequest { AccessTokenInQuery = "token" },
            _ => throw new System.ArgumentOutOfRangeException(nameof(parameter), parameter, null),
        };
        var clientRequest = new ClientRequest
        {
            AuthorizationHeader = headerScheme is null ? null : new AuthenticationHeaderValue(headerScheme, "token"),
        };

        Assert.Equal(expected, AccessTokenPresentation.SchemeOf(request, clientRequest));
    }
}
