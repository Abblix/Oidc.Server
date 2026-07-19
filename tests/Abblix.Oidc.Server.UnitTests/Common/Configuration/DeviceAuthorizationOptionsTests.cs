// Abblix OIDC Server Library
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
    [InlineData(15)]  // 120 bits — just below the floor
    public void DeviceCodeLength_BelowEntropyFloor_Throws(int lengthInBytes)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateOptions(lengthInBytes));
    }

    [Theory]
    [InlineData(16)]  // 128 bits — the floor
    [InlineData(32)]  // 256 bits — the documented default
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
