// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A removal (RFC 7592 section 2.3) takes the registration the request was authenticated against, and nothing
/// else: one rotated or removed meanwhile is not reported as removed.
/// </summary>
public class RemoveClientRequestProcessorTests
{
    private static readonly RegisteredClient Client = new(new ClientInfo("client-1"), "jti-current");

    private static RemoveClientRequestProcessor ProcessorWhere(bool registrationHeld)
    {
        var clients = new Mock<IClientInfoManager>(MockBehavior.Strict);
        clients.Setup(c => c.TryRemoveClientAsync(Client)).ReturnsAsync(registrationHeld);
        return new RemoveClientRequestProcessor(clients.Object, TimeProvider.System, SingleIssuer.Settings);
    }

    [Fact]
    public async Task ARegistrationStillHeld_IsRemoved()
    {
        var result = await ProcessorWhere(registrationHeld: true)
            .ProcessAsync(new ValidClientRequest(new ClientRequest(), Client));

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal("client-1", response.ClientId);
    }

    [Fact]
    public async Task ARegistrationNoLongerHeld_ReturnsInvalidToken()
    {
        var result = await ProcessorWhere(registrationHeld: false)
            .ProcessAsync(new ValidClientRequest(new ClientRequest(), Client));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }
}
