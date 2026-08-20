// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies the configuration-time guards on <see cref="DeviceAuthorizationOptions"/>. RFC 8628
/// Section 5.2 requires a very high entropy device code; since the device code carries no usability
/// constraint (it is never shown to the user), the option rejects byte lengths below the 128-bit
/// cryptographic floor rather than silently emitting a weak, guessable code.
/// </summary>
public class DeviceAuthorizationOptionsTests
{
    [Theory]
    [InlineData(8)]   // 64 bits
    [InlineData(15)]  // 120 bits - just below the floor
    public void DeviceCodeLength_BelowEntropyFloor_Throws(int lengthInBytes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateOptions(lengthInBytes));
    }

    [Theory]
    [InlineData(16)]  // 128 bits - the floor
    [InlineData(32)]  // 256 bits - the documented default
    public void DeviceCodeLength_AtOrAboveEntropyFloor_IsAccepted(int lengthInBytes)
    {
        var options = CreateOptions(lengthInBytes);

        Assert.Equal(lengthInBytes, options.DeviceCodeLength);
    }

    private static DeviceAuthorizationOptions CreateOptions(int deviceCodeLength) => new()
    {
        CodeLifetime = TimeSpan.FromMinutes(5),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = deviceCodeLength,
        UserCodeLength = 8,
        VerificationUri = new Uri("https://auth.example.com/device"),
    };
}
