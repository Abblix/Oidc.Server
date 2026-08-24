// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using StoredRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using WireRequest = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.BackChannelAuthentication;

/// <summary>
/// What the CIBA processor does with the session the host says authenticated.
/// </summary>
/// <remarks>
/// A device flow gives this server no way to observe who picked up the phone: the host reaches the end user,
/// the end user approves, and the host reports a session. When the request also carried an
/// <c>id_token_hint</c>, it already said who it meant, and OpenID Connect Core 1.0 Section 3.1.2.2 leaves no
/// discretion about the mismatch - the server "MUST NOT reply with an ID Token or Access Token for a
/// different user, even if they have an active session with the Authorization Server".
/// </remarks>
public class BackChannelAuthenticationRequestProcessorTests
{
    private const string Approved = "user-who-approved";
    private const string ClientId = "ciba-client";

    private readonly Mock<IBackChannelRequestStorage> _storage = new();
    private readonly Mock<IUserDeviceAuthenticationHandler> _handler = new(MockBehavior.Strict);
    private readonly Mock<ISubjectTypeConverter> _subjectTypeConverter = new(MockBehavior.Strict);
    private readonly BackChannelAuthenticationRequestProcessor _processor;

    public BackChannelAuthenticationRequestProcessorTests()
    {
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.SetupGet(o => o.Value).Returns(new OidcOptions());

        // A public client, so the session's subject is what the client sees. The pairwise direction is the
        // shared comparison's own business and is covered where it lives.
        _subjectTypeConverter
            .Setup(c => c.Convert(It.IsAny<string>(), It.IsAny<ClientInfo>()))
            .Returns((string subject, ClientInfo _) => subject);

        _storage
            .Setup(s => s.StoreAsync(It.IsAny<StoredRequest>(), It.IsAny<TimeSpan>()))
            .ReturnsAsync("auth-req-id");

        _processor = new BackChannelAuthenticationRequestProcessor(
            _storage.Object,
            options.Object,
            _handler.Object,
            TimeProvider.System,
            _subjectTypeConverter.Object);
    }

    private ValidBackChannelAuthenticationRequest Request(string? hintedSubject)
    {
        var hint = hintedSubject is null
            ? null
            : new JsonWebToken
            {
                Payload = { Subject = hintedSubject, Audiences = [ClientId] },
            };

        return new ValidBackChannelAuthenticationRequest(
            new BackChannelAuthenticationValidationContext(
                new WireRequest { Scope = [Scopes.OpenId] },
                new ClientRequest { ClientId = ClientId })
            {
                ClientInfo = new ClientInfo(ClientId),
                Scope = [new ScopeDefinition(Scopes.OpenId)],
                ExpiresIn = TimeSpan.FromMinutes(5),
                IdToken = hint,
            });
    }

    private void HostAuthenticates(string subject)
    {
        Result<AuthSession, OidcError> session = new AuthSession(
            Subject: subject,
            SessionId: "session-1",
            AuthenticationTime: DateTimeOffset.UnixEpoch,
            IdentityProvider: "test");

        _handler.Setup(h => h.InitiateAuthenticationAsync(It.IsAny<ValidBackChannelAuthenticationRequest>()))
            .Returns(Task.FromResult(session));
    }

    /// <summary>
    /// A hint naming somebody other than the end user who approved is refused, and nothing is stored.
    /// </summary>
    /// <remarks>
    /// Storing is the irreversible half: an <c>auth_req_id</c> that reached the client would be redeemable
    /// for tokens minted against the wrong session, and the client has no way to notice. The refusal
    /// therefore has to come before the store, which is what the second assertion pins.
    /// </remarks>
    [Fact]
    public async Task AHintNamingSomebodyElse_IsRefusedBeforeAnythingIsStored()
    {
        HostAuthenticates(Approved);

        var result = await _processor.ProcessAsync(Request("somebody-else"));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.AccessDenied, error.Error);
        _storage.Verify(
            s => s.StoreAsync(It.IsAny<StoredRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

    /// <summary>
    /// A hint naming the end user who approved is accepted.
    /// </summary>
    /// <remarks>
    /// The control for the case above: without it the same assertions would hold over a processor that
    /// refused every request carrying a hint at all.
    /// </remarks>
    [Fact]
    public async Task AHintNamingTheEndUserWhoApproved_IsAccepted()
    {
        HostAuthenticates(Approved);

        var result = await _processor.ProcessAsync(Request(Approved));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A request that named nobody is accepted whoever approved, which is the ordinary CIBA case.
    /// </summary>
    /// <remarks>
    /// Stated because the comparison must not become a requirement to send a hint: the parameter is optional,
    /// and a request identifying the end user by <c>login_hint</c> alone says nothing for this check to
    /// compare against.
    /// </remarks>
    [Fact]
    public async Task ARequestWithoutAHint_IsAcceptedWhoeverApproved()
    {
        HostAuthenticates(Approved);

        var result = await _processor.ProcessAsync(Request(null));

        Assert.True(result.TryGetSuccess(out _));
    }
}
