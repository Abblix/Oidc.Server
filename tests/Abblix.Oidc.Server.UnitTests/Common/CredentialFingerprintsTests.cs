// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// A configured key makes every holder of it - another node, the same node after a restart - write the same
/// fingerprint for the same credential; without one each holder draws its own key.
/// </summary>
public class CredentialFingerprintsTests
{
    private const string DeviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS";

    private static CredentialFingerprints Holding(string? key)
        => new(Options.Create(new OidcOptions { FingerprintKey = key }));

    [Fact]
    public void TwoHoldersOfOneConfiguredKey_WriteTheSameFingerprint()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(FingerprintKeyValidator.MinKeyBytes));

        Assert.Equal(Holding(key).Of(DeviceCode).ToString(), Holding(key).Of(DeviceCode).ToString());
    }

    [Fact]
    public void TwoHoldersWithoutAConfiguredKey_WriteDifferentFingerprints()
        => Assert.NotEqual(Holding(null).Of(DeviceCode).ToString(), Holding(null).Of(DeviceCode).ToString());

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("c2hvcnQ=")]
    [InlineData("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==")]
    public void AKeyThatCannotKeyTheFingerprints_IsRefusedAtStartup(string key)
    {
        var result = new FingerprintKeyValidator().Validate(null, new OidcOptions { FingerprintKey = key });

        Assert.True(result.Failed);
    }

    [Fact]
    public void ALongEnoughKey_AndNoKey_AreAccepted()
    {
        var validator = new FingerprintKeyValidator();
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(FingerprintKeyValidator.MinKeyBytes));

        Assert.True(validator.Validate(null, new OidcOptions { FingerprintKey = key }).Succeeded);
        Assert.True(validator.Validate(null, new OidcOptions()).Succeeded);
    }

    /// <summary>
    /// The check is part of what the server registers, so a key that cannot key the fingerprints stops the server when
    /// its settings are read rather than at the first record.
    /// </summary>
    [Fact]
    public void TheServerRefusesAShortKey_WhenItsSettingsAreRead()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.FingerprintKey = "c2hvcnQ=");
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddOidcOptionsValidators();
        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
    }
}
