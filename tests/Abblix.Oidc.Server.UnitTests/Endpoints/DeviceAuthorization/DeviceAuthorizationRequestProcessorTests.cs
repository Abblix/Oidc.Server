// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;
using WireRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization;

/// <summary>
/// What the device authorization endpoint hands out and what it keeps.
/// </summary>
public class DeviceAuthorizationRequestProcessorTests
{
    private const string ClientId = "device_client";
    private const string RandomPart = "random-device-code";
    private const string UserCode = "12345678";

    private static readonly DateTimeOffset Now = new(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);

    private string? _storedUnder;

    /// <summary>
    /// The device code carries the instant it expires, and the record is kept under that same code, so a poll
    /// after the record is evicted can still be told the code expired.
    /// </summary>
    [Fact]
    public async Task TheDeviceCode_CarriesItsExpiry_AndNamesTheStoredRecord()
    {
        var response = await ProcessAsync(new Uri("https://auth.example.com/device"), TestConstants.DefaultIssuer.OriginalString);

        Assert.True(ExpiringIdentifier.TryReadExpiry(response.DeviceCode, out var expiresAt));
        Assert.Equal(Now + CodeLifetime, expiresAt);
        Assert.Equal(response.DeviceCode, _storedUnder);
    }

    /// <summary>
    /// A relative verification page is one under the issuer, so a tenant's users are sent to that tenant's page,
    /// whose path resolves the tenant their user code was issued in.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/acme")]
    [InlineData("https://auth.example.com/tenants/acme/")]
    public async Task ARelativeVerificationUri_IsAPageUnderTheIssuer(string issuer)
    {
        var response = await ProcessAsync(new Uri("device", UriKind.Relative), issuer);

        Assert.Equal(new Uri("https://auth.example.com/tenants/acme/device"), response.VerificationUri);
        Assert.Equal(
            new Uri($"https://auth.example.com/tenants/acme/device?user_code={UserCode}"),
            response.VerificationUriComplete);
    }

    /// <summary>
    /// A relative page that resolves outside the issuer - from the host's root, or up out of the issuer's path -
    /// is not a page of this issuer, and under multi-tenancy resolves no tenant; it is refused rather than sent.
    /// </summary>
    [Theory]
    [InlineData("/device")]
    [InlineData("../device")]
    public async Task ARelativeVerificationUriLeavingTheIssuer_IsRefused(string relative)
        => await Assert.ThrowsAsync<InvalidOperationException>(
            () => ProcessAsync(new Uri(relative, UriKind.Relative), "https://auth.example.com/tenants/acme"));

    /// <summary>
    /// The user authenticates on the page, so one resolved under an issuer without TLS is refused, as an absolute
    /// one without it is when configured. The refusal comes before anything is stored, so a request refused this way
    /// leaves no code behind.
    /// </summary>
    [Fact]
    public async Task ARelativeVerificationUriUnderAnIssuerWithoutTls_IsRefused_BeforeACodeIsStored()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => ProcessAsync(new Uri("device", UriKind.Relative), "http://auth.example.com/tenants/acme"));

        Assert.Null(_storedUnder);
    }

    /// <summary>
    /// An absolute verification page is where the host put it, whatever the issuer.
    /// </summary>
    [Fact]
    public async Task AnAbsoluteVerificationUri_IsKeptAsConfigured()
    {
        var response = await ProcessAsync(
            new Uri("https://device.example.com/activate"), "https://auth.example.com/tenants/acme");

        Assert.Equal(new Uri("https://device.example.com/activate"), response.VerificationUri);
        Assert.Equal(
            new Uri($"https://device.example.com/activate?user_code={UserCode}"),
            response.VerificationUriComplete);
    }

    private async Task<DeviceAuthorizationResponse> ProcessAsync(Uri verificationUri, string issuer)
    {
        var storage = new Mock<IDeviceAuthorizationStorage>();
        storage
            .Setup(s => s.StoreAsync(It.IsAny<string>(), It.IsAny<StoredRequest>(), CodeLifetime))
            .Callback<string, StoredRequest, TimeSpan>((deviceCode, _, _) => _storedUnder = deviceCode)
            .Returns(Task.CompletedTask);

        var deviceCodes = new Mock<IDeviceCodeGenerator>();
        deviceCodes.Setup(g => g.GenerateDeviceCode()).Returns(RandomPart);
        var userCodes = new Mock<IUserCodeGenerator>();
        userCodes.Setup(g => g.GenerateUserCode()).Returns(UserCode);

        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.SetupGet(o => o.Value).Returns(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = CodeLifetime,
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = verificationUri,
            },
        });

        var issuerProvider = new Mock<IIssuerProvider>();
        issuerProvider.Setup(p => p.GetIssuer()).Returns(issuer);

        var processor = new DeviceAuthorizationRequestProcessor(
            storage.Object,
            deviceCodes.Object,
            userCodes.Object,
            options.Object,
            new FakeTimeProvider(Now),
            issuerProvider.Object);

        var result = await processor.ProcessAsync(new ValidDeviceAuthorizationRequest(
            new DeviceAuthorizationValidationContext(
                new WireRequest { Scope = [Scopes.OpenId] },
                new ClientRequest { ClientId = ClientId })
            {
                ClientInfo = new ClientInfo(ClientId),
            }));

        Assert.True(result.TryGetSuccess(out var response));
        return response;
    }
}
