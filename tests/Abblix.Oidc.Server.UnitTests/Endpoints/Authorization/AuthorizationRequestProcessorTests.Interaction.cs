// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    /// <summary>
    /// A step the host requires of the end user sends them to the interaction page with the selected session, before
    /// any consent is read.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_StepRequired_SendsToTheInteractionPageWithTheSession()
    {
        var request = CreateRequest();
        var session = CreateAuthSession();
        SessionsAre(session);
        _interactionRequirement.Setup(r => r.IsRequiredAsync(request, session)).ReturnsAsync(true);

        var result = await _processor.ProcessAsync(request);

        var interaction = Assert.IsType<InteractionRequired>(result);
        Assert.Same(session, interaction.AuthSession);
        Assert.Same(request.Model, interaction.Model);
        _consentsProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A step required of a request forbidding interaction is told to the client as interaction_required
    /// (OpenID Connect Core 1.0, section 3.1.2.6).
    /// </summary>
    [Fact]
    public async Task ProcessAsync_StepRequiredAndPromptNone_AnswersInteractionRequired()
    {
        var request = CreateRequest(prompt: [Prompts.None]);
        var session = CreateAuthSession();
        SessionsAre(session);
        _interactionRequirement.Setup(r => r.IsRequiredAsync(request, session)).ReturnsAsync(true);

        var result = await _processor.ProcessAsync(request);

        var error = Assert.IsType<AuthorizationError>(result);
        Assert.Equal(ErrorCodes.InteractionRequired, error.Error);
        Assert.Equal(request.Model.RedirectUri, error.RedirectUri);
        _consentsProvider.VerifyNoOtherCalls();
    }

    /// <summary>
    /// A login the request asks for and the session has not answered yet comes first, and the host is not asked
    /// about a session the end user is about to replace.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_LoginNotYetAnswered_SendsToLoginWithoutAskingForAStep()
    {
        var request = CreateRequest(prompt: [Prompts.Login]);
        SessionsAre(CreateAuthSession());
        _interactionRequirement
            .Setup(r => r.IsRequiredAsync(It.IsAny<ValidAuthorizationRequest>(), It.IsAny<AuthSession>()))
            .ReturnsAsync(true);

        var result = await _processor.ProcessAsync(request);

        Assert.IsType<LoginRequired>(result);
        _interactionRequirement.Verify(
            r => r.IsRequiredAsync(It.IsAny<ValidAuthorizationRequest>(), It.IsAny<AuthSession>()),
            Times.Never);
    }

    /// <summary>
    /// No step required lets the request through to the code, as it went before the host was asked.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_NoStepRequired_IssuesTheCode()
    {
        var request = CreateRequest();
        var session = CreateAuthSession();
        var capture = SetupSuccessfulAuthCodeFlow(request, session, CreateConsents());
        _interactionRequirement.Setup(r => r.IsRequiredAsync(request, session)).ReturnsAsync(false);

        var result = await _processor.ProcessAsync(request);

        Assert.IsType<SuccessfullyAuthenticated>(result);
        Assert.Same(session, capture.Grant?.AuthSession);
        _interactionRequirement.Verify(r => r.IsRequiredAsync(request, session), Times.Once);
    }

    /// <summary>
    /// The host is asked about the session the request proceeds with, so several sessions go to account selection
    /// first, and the host is not asked.
    /// </summary>
    [Fact]
    public async Task ProcessAsync_SeveralSessions_SelectsAnAccountWithoutAskingForAStep()
    {
        var request = CreateRequest();
        SessionsAre(CreateAuthSession("s1"), CreateAuthSession("s2"));
        _interactionRequirement
            .Setup(r => r.IsRequiredAsync(It.IsAny<ValidAuthorizationRequest>(), It.IsAny<AuthSession>()))
            .ReturnsAsync(true);

        var result = await _processor.ProcessAsync(request);

        Assert.IsType<AccountSelectionRequired>(result);
        _interactionRequirement.Verify(
            r => r.IsRequiredAsync(It.IsAny<ValidAuthorizationRequest>(), It.IsAny<AuthSession>()),
            Times.Never);
    }

    private void SessionsAre(params AuthSession[] sessions)
        => _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(sessions.ToAsyncEnumerable());
}
