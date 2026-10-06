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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Consents;

/// <summary>
/// Pins that a request whose <c>prompt</c> list holds consent asks the end user for every scope again, wherever
/// consent stands in the list, and that any other request is answered by the consents the host keeps.
/// </summary>
public class PromptConsentDecoratorTests
{
    private static readonly AuthSession Session = new("subject", "session", DateTimeOffset.UnixEpoch, "local");

    private static ValidAuthorizationRequest RequestWith(string[] prompt) => new(new AuthorizationValidationContext(
        new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
            Prompt = prompt,
        })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        Scope = [StandardScopes.OpenId],
    });

    [Theory]
    [InlineData(Prompts.Consent)]
    [InlineData(Prompts.Login, Prompts.Consent)]
    public async Task APromptHoldingConsent_LeavesEveryScopePending(params string[] prompt)
    {
        var inner = new Mock<IUserConsentsProvider>(MockBehavior.Strict);
        var request = RequestWith(prompt);

        var consents = await new PromptConsentDecorator(inner.Object).GetUserConsentsAsync(request, Session);

        Assert.Equal(request.Scope, consents.Pending.Scopes);
    }

    [Fact]
    public async Task APromptWithoutConsent_IsAnsweredByTheHostsConsents()
    {
        var request = RequestWith([Prompts.Login]);
        var kept = new UserConsents();
        var inner = new Mock<IUserConsentsProvider>(MockBehavior.Strict);
        inner.Setup(provider => provider.GetUserConsentsAsync(request, Session)).ReturnsAsync(kept);

        var consents = await new PromptConsentDecorator(inner.Object).GetUserConsentsAsync(request, Session);

        Assert.Same(kept, consents);
    }
}
