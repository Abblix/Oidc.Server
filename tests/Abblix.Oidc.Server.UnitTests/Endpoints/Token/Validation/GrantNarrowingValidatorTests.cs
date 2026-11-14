// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// A token request may only narrow its grant: a resource it names outside the grant refuses it, whether the grant holds
/// other resources or none, and so does a scope naming none of the granted scopes.
/// </summary>
public class GrantNarrowingValidatorTests
{
    private const string ClientId = "client";
    private const string Orders = "https://orders.example.com";
    private const string Payments = "https://payments.example.com";

    /// <summary>
    /// Every resource the request names has to be one its grant holds.
    /// </summary>
    [Theory]
    [InlineData(new[] { Orders }, new[] { Orders }, null)]
    [InlineData(new[] { Orders, Payments }, new[] { Orders }, null)]
    [InlineData(new[] { Orders }, new string[0], null)]
    [InlineData(null, new string[0], null)]
    [InlineData(new[] { Orders }, new[] { Payments }, ErrorCodes.InvalidTarget)]
    [InlineData(new[] { Orders }, new[] { Orders, Payments }, ErrorCodes.InvalidTarget)]
    [InlineData(null, new[] { Orders }, ErrorCodes.InvalidTarget)]
    [InlineData(new string[0], new[] { Orders }, ErrorCodes.InvalidTarget)]
    public async Task AResourceOutsideTheGrant_IsRefused(string[]? granted, string[] named, string? error)
    {
        var refusal = await ValidateAsync(
            [Scopes.OpenId],
            granted?.Select(uri => new Uri(uri)).ToArray(),
            [],
            named.Select(uri => new ResourceDefinition(new Uri(uri))).ToArray());

        Assert.Equal(error, refusal?.Error);
        if (error is not null)
            Assert.Equal(ResourceRefusals.NotGranted, refusal?.ErrorDescription);
    }

    /// <summary>
    /// A request naming none of the granted scopes is refused, while one naming some of them is narrowed to those.
    /// </summary>
    [Theory]
    [InlineData(new[] { Scopes.OpenId, Scopes.Profile }, new[] { Scopes.Email }, ErrorCodes.InvalidScope)]
    [InlineData(new string[0], new[] { Scopes.Email }, ErrorCodes.InvalidScope)]
    [InlineData(new[] { Scopes.OpenId, Scopes.Profile }, new[] { Scopes.Profile, Scopes.Email }, null)]
    [InlineData(new[] { Scopes.OpenId }, new string[0], null)]
    public async Task AScopeNamingNoneGranted_IsRefused(string[] granted, string[] named, string? error)
    {
        var refusal = await ValidateAsync(
            granted,
            null,
            named.Select(scope => new ScopeDefinition(scope)).ToArray(),
            []);

        Assert.Equal(error, refusal?.Error);
        if (error is not null)
            Assert.Equal(ScopeRefusals.NotGranted, refusal?.ErrorDescription);
    }

    private static Task<OidcError?> ValidateAsync(
        string[] grantedScope,
        Uri[]? grantedResources,
        ScopeDefinition[] scope,
        ResourceDefinition[] resources)
    {
        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.RefreshToken },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = new ClientInfo(ClientId),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(ClientId, grantedScope, null, grantedResources)),
            Scope = scope,
            Resources = resources,
        };

        return new GrantNarrowingValidator().ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);
    }
}
