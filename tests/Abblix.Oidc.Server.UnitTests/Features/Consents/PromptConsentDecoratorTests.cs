// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
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
/// Pins how a request whose <c>prompt</c> list holds consent is answered: every scope pending again until the end
/// user gives consent on the page the server sent them to, and the host's consents once they have; any other
/// request is answered by the consents the host keeps.
/// </summary>
public class PromptConsentDecoratorTests
{
    private static readonly AuthSession Session = new("subject", "session", DateTimeOffset.UnixEpoch, "local");
    private static readonly DateTimeOffset ConsentPageShownAt = new(2026, 10, 6, 12, 0, 0, TimeSpan.Zero);

    private static ValidAuthorizationRequest RequestWith(
        string[] prompt,
        DateTimeOffset? consentPageShownAt = null) => new(new AuthorizationValidationContext(
        new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = TestConstants.DefaultRedirectUri,
            Scope = [Scopes.OpenId],
            Prompt = prompt,
            Prompted = consentPageShownAt is { } shownAt
                ? new Dictionary<string, DateTimeOffset> { [Prompts.Consent] = shownAt }
                : null,
        })
    {
        ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        Scope = [StandardScopes.OpenId],
    });

    private static Task<UserConsents> AnswerAsync(ValidAuthorizationRequest request, UserConsents kept)
    {
        var inner = new Mock<IUserConsentsProvider>(MockBehavior.Strict);
        inner.Setup(provider => provider.GetUserConsentsAsync(request, Session)).ReturnsAsync(kept);
        return new PromptConsentDecorator(inner.Object).GetUserConsentsAsync(request, Session);
    }

    [Theory]
    [InlineData(Prompts.Consent)]
    [InlineData(Prompts.Login, Prompts.Consent)]
    public async Task APromptHoldingConsent_BeforeTheConsentPage_LeavesEveryScopePending(params string[] prompt)
    {
        var request = RequestWith(prompt);

        var consents = await AnswerAsync(request, new UserConsents { GivenAt = ConsentPageShownAt });

        Assert.Equal(request.Scope, consents.Pending.Scopes);
    }

    [Fact]
    public async Task ConsentGivenOnTheConsentPage_AnswersThePrompt()
    {
        var request = RequestWith([Prompts.Consent], ConsentPageShownAt);
        var given = new UserConsents { GivenAt = ConsentPageShownAt.AddSeconds(5) };

        Assert.Same(given, await AnswerAsync(request, given));
    }

    [Fact]
    public async Task ConsentGivenBeforeTheConsentPage_LeavesEveryScopePending()
    {
        var request = RequestWith([Prompts.Consent], ConsentPageShownAt);

        var consents = await AnswerAsync(request, new UserConsents { GivenAt = ConsentPageShownAt.AddMinutes(-1) });

        Assert.Equal(request.Scope, consents.Pending.Scopes);
    }

    /// <summary>
    /// A consent the host records no moment for, as one the server grants on its own, does not answer the prompt.
    /// </summary>
    [Fact]
    public async Task ConsentWithoutAMoment_LeavesEveryScopePending()
    {
        var request = RequestWith([Prompts.Consent], ConsentPageShownAt);

        var consents = await AnswerAsync(request, new UserConsents());

        Assert.Equal(request.Scope, consents.Pending.Scopes);
    }

    [Fact]
    public async Task APromptWithoutConsent_IsAnsweredByTheHostsConsents()
    {
        var request = RequestWith([Prompts.Login]);
        var kept = new UserConsents();

        Assert.Same(kept, await AnswerAsync(request, kept));
    }
}
