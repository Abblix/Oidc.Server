// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// How a parameter in the query is read, the same on both hosts: RFC 6749 section 3.1 says "Parameters sent
/// without a value MUST be treated as if they were omitted from the request".
/// </summary>
public partial class PromptReturnTripTests
{
    /// <summary>
    /// A typed parameter sent without a value is absent, as the request without it: it goes on to the login page.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims)]
    [InlineData(AuthorizationRequest.Parameters.MaxAge)]
    public async Task EmptyTypedParameter_InTheQuery_IsTakenAsAbsent(string name)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var query = AuthorizeParameters(Prompts.Login);
        query[name] = string.Empty;

        var sentTo = await RedirectOf(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query));

        Assert.Equal(LoginPath, PathOf(sentTo));
    }

    /// <summary>
    /// A typed parameter whose value is whitespace alone, or does not read as its type, is an invalid value and is
    /// refused with a 400 (RFC 6749 section 4.1.2.1: invalid_request "includes an invalid parameter value").
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims, " ")]
    [InlineData(AuthorizationRequest.Parameters.Claims, "{not json")]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, " ")]
    [InlineData(AuthorizationRequest.Parameters.MaxAge, "abc")]
    public async Task InvalidTypedParameter_InTheQuery_IsRefused(string name, string value)
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var query = AuthorizeParameters(Prompts.Login);
        query[name] = value;

        Assert.Equal(
            HttpStatusCode.BadRequest,
            await StatusOfAsync(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query)));
    }
}
