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
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
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

    private static readonly DateTimeOffset Now = new(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The device code carries the instant it expires, and the record is kept under that same code, so a poll
    /// after the record is evicted can still be told the code expired.
    /// </summary>
    [Fact]
    public async Task TheDeviceCode_CarriesItsExpiry_AndNamesTheStoredRecord()
    {
        var storage = new Mock<IDeviceAuthorizationStorage>();
        string? storedUnder = null;
        storage
            .Setup(s => s.StoreAsync(It.IsAny<string>(), It.IsAny<StoredRequest>(), CodeLifetime))
            .Callback<string, StoredRequest, TimeSpan>((deviceCode, _, _) => storedUnder = deviceCode)
            .Returns(Task.CompletedTask);

        var deviceCodes = new Mock<IDeviceCodeGenerator>();
        deviceCodes.Setup(g => g.GenerateDeviceCode()).Returns(RandomPart);
        var userCodes = new Mock<IUserCodeGenerator>();
        userCodes.Setup(g => g.GenerateUserCode()).Returns("12345678");

        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.SetupGet(o => o.Value).Returns(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = CodeLifetime,
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = new Uri("https://auth.example.com/device"),
            },
        });

        var processor = new DeviceAuthorizationRequestProcessor(
            storage.Object, deviceCodes.Object, userCodes.Object, options.Object, new FakeTimeProvider(Now));

        var result = await processor.ProcessAsync(new ValidDeviceAuthorizationRequest(
            new DeviceAuthorizationValidationContext(
                new WireRequest { Scope = [Scopes.OpenId] },
                new ClientRequest { ClientId = ClientId })
            {
                ClientInfo = new ClientInfo(ClientId),
            }));

        Assert.True(result.TryGetSuccess(out var response));
        Assert.True(ExpiringIdentifier.TryReadExpiry(response.DeviceCode, out var expiresAt));
        Assert.Equal(Now + CodeLifetime, expiresAt);
        Assert.Equal(response.DeviceCode, storedUnder);
    }
}
