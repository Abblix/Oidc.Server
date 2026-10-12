// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Client.Features.BackChannelAuthentication;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// CIBA in poll mode against the real provider, as far as a suite with no human in it can go.
/// </summary>
/// <remarks>
/// The middle of this flow is a person answering on their own device, and nothing here can be that person.
/// What the test does instead is play the host: it reports the answer through the seam the provider exposes
/// for exactly that, <c>IAuthenticationCompletionHandler.CompleteAsync</c>, which is the only production
/// path that writes the Authenticated status the token endpoint reads. Returning a session from the device
/// handler does not do it, and an earlier attempt that assumed otherwise polled for five minutes and expired.
///
/// With that one line supplied, everything else here is the real thing end to end: the request the provider
/// accepts, the acknowledgement it returns, and the identifier redeeming into tokens under the grant CIBA
/// section 10.1 names.
///
/// The rules of the waiting - the interval, what <c>slow_down</c> does to it - are proved in the unit suite on
/// a clock it controls, which is also the only place a provider can be made to answer <c>slow_down</c> on cue.
/// </remarks>
public class BackChannelAuthenticationTests : IAsyncLifetime
{
    private const string ClientId = "e2e-ciba";
    private const string PollDeliveryMode = "poll";
    private const string Subject = "e2e-subject";

    private readonly ClientAgainstServerFixture _fixture = new();

    /// <summary>
    /// Stands in for the part of a provider this repository does not write: whatever reaches the person and
    /// asks them. It answers yes immediately, which is what makes a whole CIBA round trip observable here.
    /// </summary>
    /// <remarks>
    /// A real one would notify a phone and return only once the person had answered, so the tokens would
    /// arrive after several polls rather than the first. That difference belongs to the waiting, which has
    /// its own tests; what this handler leaves intact is everything else.
    /// </remarks>
    private sealed class ImmediateApproval(ISessionIdGenerator sessionIds, TimeProvider clock)
        : IUserDeviceAuthenticationHandler
    {
        public Task<Result<AuthSession, OidcError>> InitiateAuthenticationAsync(
            ValidBackChannelAuthenticationRequest request)
            => Task.FromResult<Result<AuthSession, OidcError>>(
                new AuthSession(
                    Subject: Subject,
                    SessionId: sessionIds.GenerateSessionId(),
                    AuthenticationTime: clock.GetUtcNow(),
                    IdentityProvider: Abblix.Oidc.Server.Common.Constants.GrantTypes.Ciba));
    }

    public async ValueTask InitializeAsync()
    {
        _fixture.ConfigureProviderServices = services =>
        {
            services.AddSingleton<IUserDeviceAuthenticationHandler, ImmediateApproval>();

            services.PostConfigure<OidcOptions>(options =>
            {
                // A second rather than the default five. The wait in these tests is real, because the
                // provider measures the gap between polls on its own clock: a client waiting on a stopped
                // one would poll in no time at all and be told to slow down forever.
                options.BackChannelAuthentication.PollingInterval = TimeSpan.FromSeconds(1);

                options.Clients =
                [
                    ..options.Clients,
                    new ClientInfo(ClientId)
                    {
                        ClientSecrets =
                        [
                            new ClientSecret
                            {
                                Sha512Hash = SHA512.HashData(
                                    Encoding.UTF8.GetBytes(ClientAgainstServerFixture.ClientSecret)),
                            },
                        ],
                        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                        AllowedGrantTypes = [Abblix.Oidc.Server.Common.Constants.GrantTypes.Ciba],
                        BackChannelTokenDeliveryMode = PollDeliveryMode,
                    },
                ];
            });
        };

        await _fixture.InitializeAsync();
    }

    public async ValueTask DisposeAsync() => await _fixture.DisposeAsync();

    private static Task<BackChannelAuthenticationResponse> AskAsync(
        IServiceProvider client, CancellationToken cancellationToken, string? bindingMessage = null)
        => client.GetRequiredService<IBackChannelAuthenticationService>()
            .RequestAsync(
                new BackChannelAuthenticationRequest
                {
                    Scopes = [Abblix.Oidc.Client.Common.Scopes.OpenId],
                    LoginHint = Subject,
                    BindingMessage = bindingMessage,
                },
                cancellationToken);

    /// <summary>
    /// The provider accepts the request and acknowledges it with what identifies it afterwards, per CIBA
    /// section 7.3.
    /// </summary>
    [Fact]
    public async Task TheProviderAcknowledgesTheRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var acknowledgement = await AskAsync(client, cancellationToken, bindingMessage: "W4ZE");

        Assert.NotEmpty(acknowledgement.AuthenticationRequestId);
        Assert.True(acknowledgement.Lifetime > TimeSpan.Zero);
        Assert.True(acknowledgement.PollingInterval > TimeSpan.Zero);
    }

    /// <summary>
    /// Once the person has answered, the identifier this client kept redeems into tokens about them.
    /// </summary>
    /// <remarks>
    /// The answering is driven from the test rather than waited for, because it is the one part of CIBA that
    /// belongs to the host rather than to either library. Nothing on the provider's request path marks a
    /// request answered: the status lives in <c>IBackChannelRequestStorage</c>, and the only production code
    /// that writes <c>Authenticated</c> runs from <c>IAuthenticationCompletionHandler.CompleteAsync</c>,
    /// which a host calls when its own out-of-band flow comes back with a yes. That is why returning a
    /// session from the device handler is not enough, and why an earlier attempt at this test polled for
    /// five minutes and expired.
    ///
    /// No waiting is needed after the completion either: the grant handler evaluates its Authenticated arm
    /// before the one that would answer <c>slow_down</c>, so a request that has been answered is redeemable
    /// at once.
    /// </remarks>
    [Fact]
    public async Task AnAnsweredRequestRedeemsIntoTokensForThatPerson()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var acknowledgement = await AskAsync(client, cancellationToken);
        await AnswerAsync(acknowledgement.AuthenticationRequestId);

        var tokens = await client.GetRequiredService<ITokenRequestService>()
            .RedeemAuthenticationRequestAsync(acknowledgement.AuthenticationRequestId, cancellationToken);

        Assert.NotEmpty(tokens.AccessToken);
        Assert.NotNull(tokens.IdToken);
    }

    /// <summary>
    /// The identifier is single-use: a second redemption of an answered request is refused.
    /// </summary>
    /// <remarks>
    /// Without this the test above would pass against a token endpoint that issued tokens to anyone
    /// presenting any identifier, which is the failure it exists to rule out.
    /// </remarks>
    [Fact]
    public async Task AnIdentifierAlreadyRedeemedIsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var acknowledgement = await AskAsync(client, cancellationToken);
        await AnswerAsync(acknowledgement.AuthenticationRequestId);

        var tokenRequests = client.GetRequiredService<ITokenRequestService>();
        await tokenRequests.RedeemAuthenticationRequestAsync(
            acknowledgement.AuthenticationRequestId, cancellationToken);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => tokenRequests.RedeemAuthenticationRequestAsync(
                acknowledgement.AuthenticationRequestId, cancellationToken));

        Assert.NotNull(exception.Error);
    }

    /// <summary>
    /// Plays the part of the host: reports that the person said yes.
    /// </summary>
    /// <remarks>
    /// Reaches into the provider's own container because that is where the seam is. The storage is a
    /// singleton and the completion handler is scoped, so a scope covers both, and both are the very
    /// instances the live endpoint uses.
    /// </remarks>
    private async Task AnswerAsync(string authenticationRequestId)
    {
        using var scope = _fixture.Services.CreateScope();

        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();
        var pending = await storage.TryGetAsync(authenticationRequestId);
        Assert.NotNull(pending);

        await scope.ServiceProvider.GetRequiredService<IAuthenticationCompletionHandler>()
            .CompleteAsync(authenticationRequestId, pending, TimeSpan.FromMinutes(5));
    }
}
