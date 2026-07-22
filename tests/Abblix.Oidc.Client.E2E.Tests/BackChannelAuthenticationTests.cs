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
/// What the real provider settles instead is everything around them: whether the parameters this client sends
/// are the ones its backchannel endpoint expects, whether the acknowledgement carries what the polling needs,
/// and whether the acknowledgement carries what the polling needs.
///
/// The redemption is NOT covered here, and deliberately so rather than by oversight. Returning an AuthSession
/// from the handler below does not mark the request answered as far as this provider's token endpoint is
/// concerned: a client polling afterwards is told the request is still pending until it expires. Whatever does
/// complete a CIBA request on the provider side is its own piece of work, and a test written before that is
/// understood would either sit for five minutes or assert something untrue.
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
}
