// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.EndSession.Validation;

/// <summary>
/// Unit tests for <see cref="ConfirmationValidator"/>, which decides whether the end user has to be asked before
/// a logout request is acted upon (OpenID Connect RP-Initiated Logout 1.0 section 2).
/// </summary>
public class ConfirmationValidatorTests
{
    private const string CurrentSubject = "user-b";
    private const string CurrentSessionId = "session-b";

    private readonly Mock<IAuthSessionService> _authSessionService = new(MockBehavior.Strict);
    private readonly ConfirmationValidator _validator;

    public ConfirmationValidatorTests()
    {
        // These rows exercise public clients (the default subject type), so a converter with no pairwise settings
        // is the production path: it passes a subject through unchanged.
        _validator = new ConfirmationValidator(_authSessionService.Object, new SubjectTypeConverter());
        SignedIn(null);
    }

    /// <summary>
    /// Answers the current session for every read, or none when <paramref name="session"/> is null.
    /// </summary>
    private void SignedIn(AuthSession? session)
        => _authSessionService.Setup(s => s.AuthenticateAsync()).ReturnsAsync(session);

    private static AuthSession Session(string subject, string sessionId)
        => new(subject, sessionId, DateTimeOffset.UnixEpoch, "local");

    private static EndSessionValidationContext CreateContext(
        bool? confirmed = null,
        string? idTokenHint = null,
        string? hintSubject = null,
        string? hintSessionId = null)
    {
        var request = new EndSessionRequest
        {
            Confirmed = confirmed,
            IdTokenHint = idTokenHint,
        };

        var context = new EndSessionValidationContext(request)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
        };

        if (hintSubject != null || hintSessionId != null)
        {
            context.IdToken = new JsonWebToken
            {
                Payload =
                {
                    Subject = hintSubject,
                    SessionId = hintSessionId,
                },
            };
        }

        return context;
    }

    /// <summary>
    /// A request the host has already had confirmed needs nothing else, hint or no hint.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithConfirmedRequest_ShouldSucceed()
    {
        var error = await _validator.ValidateAsync(CreateContext(confirmed: true));

        Assert.Null(error);
    }

    /// <summary>
    /// A hint naming the session that is signed in stands in for the confirmation, which is what lets an ordinary
    /// logout go through without a page in between.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingTheCurrentSession_ShouldSucceed()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: false,
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintSessionId: CurrentSessionId));

        Assert.Null(error);
    }

    /// <summary>
    /// An ID token carries a session identifier only when the deployment issues one, so a hint without it is
    /// judged by its subject alone.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingTheCurrentSubjectAndNoSession_ShouldSucceed()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: false,
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject));

        Assert.Null(error);
    }

    /// <summary>
    /// A hint about somebody else does not speak for the person signed in now: RP-Initiated Logout 1.0 section 2
    /// says the OP "MUST ask the End-User this question ... if the supplied ID Token does not belong to the
    /// current OP session with the RP and/or currently logged in End-User". Without this, a client holding an old
    /// ID token of any end user could sign out whoever is there now.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingAnotherSubject_ShouldReturnError()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: false,
            idTokenHint: "id_token_value",
            hintSubject: "user-a",
            hintSessionId: CurrentSessionId));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }

    /// <summary>
    /// The same person can hold an ID token from a session that has since been replaced, and that token names a
    /// session this request is not about.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithHintNamingAnotherSession_ShouldReturnError()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: false,
            idTokenHint: "id_token_value",
            hintSubject: CurrentSubject,
            hintSessionId: "session-a"));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }

    /// <summary>
    /// A confirmation the host already obtained decides the request, however stale the hint is.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithConfirmationAndAMismatchingHint_ShouldSucceed()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: true,
            idTokenHint: "id_token_value",
            hintSubject: "user-a"));

        Assert.Null(error);
    }

    /// <summary>
    /// With nobody signed in there is no session to end and nobody to ask, so the request passes and the
    /// processing answers with the redirect alone.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithNobodySignedIn_ShouldSucceed()
    {
        var error = await _validator.ValidateAsync(CreateContext(
            confirmed: false,
            idTokenHint: "id_token_value",
            hintSubject: "user-a"));

        Assert.Null(error);
    }

    /// <summary>
    /// A request with neither a confirmation nor a hint is the case the confirmation step was written for.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(false)]
    public async Task ValidateAsync_WithoutConfirmationOrIdTokenHint_ShouldReturnError(bool? confirmed)
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(confirmed));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
        Assert.Contains("requires to be confirmed", error.ErrorDescription);
    }

    /// <summary>
    /// An empty hint is no hint at all.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithEmptyIdTokenHint_ShouldReturnError()
    {
        SignedIn(Session(CurrentSubject, CurrentSessionId));

        var error = await _validator.ValidateAsync(CreateContext(confirmed: false, idTokenHint: ""));

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.ConfirmationRequired, error.Error);
    }
}
