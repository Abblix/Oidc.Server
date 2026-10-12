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
using Abblix.Oidc.Client.Features.DeviceAuthorization;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// RFC 8628 against the real provider, as far as a suite with no human in it can go.
/// </summary>
/// <remarks>
/// What is answerable here is the shape of both requests and the meaning of what comes back: whether this
/// provider accepts the device authorization request as this client forms it, and whether the refusal it
/// gives an unauthorized code is the one this client is written to poll through.
///
/// What is not answerable is the middle of the flow. Section 3.3 has a person open the verification address
/// and type the user code, and the tokens exist only afterwards; nothing in this suite can be that person.
/// The waiting itself, including the interval and <c>slow_down</c>, is therefore proved in the unit suite on
/// a stopped clock, which is also the only place a provider can be made to answer <c>slow_down</c> on cue.
/// </remarks>
public class DeviceAuthorizationTests : IAsyncLifetime
{
    private const string ClientId = "e2e-device";

    private readonly ClientAgainstServerFixture _fixture = new();

    public async ValueTask InitializeAsync()
    {
        _fixture.ConfigureProviderServices = services => services.PostConfigure<OidcOptions>(options =>
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
                    AllowedGrantTypes = [Abblix.Oidc.Server.Common.Constants.GrantTypes.DeviceAuthorization],
                },
            ]);

        await _fixture.InitializeAsync();
    }

    public async ValueTask DisposeAsync() => await _fixture.DisposeAsync();

    /// <summary>
    /// The provider hands out the pair RFC 8628 section 3.2 describes, and every member this client requires
    /// of it is there.
    /// </summary>
    [Fact]
    public async Task TheProviderIssuesACodePairForTheDevice()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var authorization = await client.GetRequiredService<IDeviceAuthorizationService>()
            .RequestAsync(cancellationToken: cancellationToken);

        Assert.NotEmpty(authorization.DeviceCode);
        Assert.NotEmpty(authorization.UserCode);
        Assert.StartsWith(
            ClientAgainstServerFixture.Issuer, authorization.VerificationUri, StringComparison.Ordinal);
        Assert.True(authorization.Lifetime > TimeSpan.Zero);

        // Whether the provider names an interval is its business; that a client always has one to wait is
        // this client's, and section 3.2 fixes the fallback at five seconds.
        Assert.True(authorization.PollingInterval >= TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// A code nobody has authorized yet is refused with one of the two codes the polling continues through,
    /// and with the two spelled as this client expects them.
    /// </summary>
    /// <remarks>
    /// The constants this client polls on are only worth anything if they are the strings the provider
    /// actually sends, and no unit test can establish that: a stub says whatever the same hand wrote into it.
    ///
    /// Which of the two arrives depends on how soon the poll came, and this one comes at once, without the
    /// interval the flow calls for - so this provider answers <c>slow_down</c> rather than
    /// <c>authorization_pending</c>. That is the specification working as written: section 3.5 has a client
    /// wait "before each new request", the first one included, and a provider is entitled to say so when it
    /// does not. It also settles something the unit tests can only assert about themselves - that waiting
    /// before the first attempt is a rule with a counterparty behind it, not a nicety.
    /// </remarks>
    [Fact]
    public async Task AnUnauthorizedCodeIsRefusedWithACodeThePollingContinuesThrough()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var client = _fixture.CreateOidcClient(clientId: ClientId);

        var authorization = await client.GetRequiredService<IDeviceAuthorizationService>()
            .RequestAsync(cancellationToken: cancellationToken);

        var exception = await Assert.ThrowsAsync<TokenRequestException>(
            () => client.GetRequiredService<ITokenRequestService>()
                .RedeemDeviceCodeAsync(authorization.DeviceCode, cancellationToken));

        Assert.Contains(
            exception.Error,
            new[] { TokenErrorCodes.AuthorizationPending, TokenErrorCodes.SlowDown });
    }
}
