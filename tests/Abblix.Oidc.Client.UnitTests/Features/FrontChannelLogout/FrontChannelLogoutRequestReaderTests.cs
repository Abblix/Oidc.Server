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

using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.FrontChannelLogout;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.FrontChannelLogout;

/// <summary>
/// Reading a front-channel logout request, and refusing the shapes no provider was allowed to send.
/// </summary>
public class FrontChannelLogoutRequestReaderTests
{
    private const string Issuer = "https://provider.example.com";

    private static IFrontChannelLogoutRequestReader Create(bool sessionRequired = false)
        => new FrontChannelLogoutRequestReader(
            new ConfiguredMetadataProvider(new ProviderMetadata { Issuer = Issuer }),
            Options.Create(new FrontChannelLogoutOptions { SessionRequired = sessionRequired }));

    private static Task<FrontChannelLogoutNotification> Read(
        bool sessionRequired = false, (string Name, string? Value)[]? parameters = null)
        => Create(sessionRequired).ReadAsync(
            (parameters ?? [])
                .ToDictionary(entry => entry.Name, entry => entry.Value, StringComparer.Ordinal),
            TestContext.Current.CancellationToken);

    /// <summary>
    /// A request naming nothing is the plain case section 2 allows: the parameters are the provider's to add
    /// or omit, and a client that keeps one session per browser has nothing to tell apart.
    /// </summary>
    [Fact]
    public async Task ARequestNamingNothingIsRead()
    {
        var notification = await Read();

        Assert.Null(notification.Issuer);
        Assert.Null(notification.SessionId);
    }

    /// <summary>
    /// A request naming both is read, and both reach the host.
    /// </summary>
    [Fact]
    public async Task ARequestNamingBothIsRead()
    {
        var notification = await Read(
            parameters: [("iss", Issuer), ("sid", "the-session")]);

        Assert.Equal(Issuer, notification.Issuer);
        Assert.Equal("the-session", notification.SessionId);
    }

    /// <summary>
    /// Section 2: "The OP MAY add these query parameters when rendering the logout URI, and if either is
    /// included, both MUST be." One without the other is a request no provider was allowed to send.
    /// </summary>
    [Theory]
    [InlineData("iss", Issuer)]
    [InlineData("sid", "the-session")]
    public async Task OneWithoutTheOtherIsRefused(string name, string value)
        => await Assert.ThrowsAsync<FrontChannelLogoutException>(
            () => Read(parameters: [(name, value)]));

    /// <summary>
    /// A parameter present but empty identifies nothing, so it counts as absent - and then its partner is
    /// travelling alone, which is the case above.
    /// </summary>
    [Fact]
    public async Task AnEmptyParameterCountsAsAbsent()
        => await Assert.ThrowsAsync<FrontChannelLogoutException>(
            () => Read(parameters: [("iss", ""), ("sid", "the-session")]));

    /// <summary>
    /// With the requirement set, a request naming neither is refused rather than acted on blindly.
    /// </summary>
    [Fact]
    public async Task WithSessionRequiredARequestNamingNothingIsRefused()
        => await Assert.ThrowsAsync<FrontChannelLogoutException>(() => Read(sessionRequired: true));

    /// <summary>
    /// With the requirement set, a request naming both is still read.
    /// </summary>
    [Fact]
    public async Task WithSessionRequiredARequestNamingBothIsRead()
    {
        var notification = await Read(
            sessionRequired: true, parameters: [("iss", Issuer), ("sid", "the-session")]);

        Assert.Equal("the-session", notification.SessionId);
    }

    /// <summary>
    /// An issuer this client does not use is refused. Our check rather than the specification's, and not
    /// primarily a defence - the endpoint takes no token - but so that an unverified identifier is not
    /// handed on as though this client had recognised it.
    /// </summary>
    [Fact]
    public async Task AnotherIssuerIsRefused()
        => await Assert.ThrowsAsync<FrontChannelLogoutException>(
            () => Read(parameters: [("iss", "https://elsewhere.example.com"), ("sid", "the-session")]));
}
