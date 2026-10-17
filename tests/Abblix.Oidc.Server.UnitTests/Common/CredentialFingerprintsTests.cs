// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
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
        => new(Options.Create(new OidcOptions { LogFingerprintKey = key }));

    [Fact]
    public void TwoHoldersOfOneConfiguredKey_WriteTheSameFingerprint()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(LogFingerprintKeyValidator.MinKeyBytes));

        Assert.Equal(Holding(key).Of(DeviceCode).ToString(), Holding(key).Of(DeviceCode).ToString());
    }

    [Fact]
    public void TwoHoldersWithoutAConfiguredKey_WriteDifferentFingerprints()
        => Assert.NotEqual(Holding(null).Of(DeviceCode).ToString(), Holding(null).Of(DeviceCode).ToString());

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("c2hvcnQ=")]
    public void AKeyThatCannotKeyTheFingerprints_IsRefusedAtStartup(string key)
    {
        var result = new LogFingerprintKeyValidator().Validate(null, new OidcOptions { LogFingerprintKey = key });

        Assert.True(result.Failed);
    }

    [Fact]
    public void ALongEnoughKey_AndNoKey_AreAccepted()
    {
        var validator = new LogFingerprintKeyValidator();
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(LogFingerprintKeyValidator.MinKeyBytes));

        Assert.True(validator.Validate(null, new OidcOptions { LogFingerprintKey = key }).Succeeded);
        Assert.True(validator.Validate(null, new OidcOptions()).Succeeded);
    }
}
