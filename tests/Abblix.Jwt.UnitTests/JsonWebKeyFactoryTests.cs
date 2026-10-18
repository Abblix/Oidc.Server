// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The HMAC keys the factory generates: as long as the hash output of their algorithm by default, which is the
/// smallest key the signer accepts.
/// </summary>
public class JsonWebKeyFactoryTests
{
    /// <summary>A default HMAC key is exactly the size RFC 7518 section 3.2 requires of its algorithm.</summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256, 32)]
    [InlineData(SigningAlgorithms.HS384, 48)]
    [InlineData(SigningAlgorithms.HS512, 64)]
    public void ADefaultHmacKey_IsAsLongAsItsHash(string algorithm, int bytes)
        => Assert.Equal(bytes, JsonWebKeyFactory.CreateHmac(algorithm).KeyValue!.Length);

    /// <summary>A default HMAC key is not generated for an algorithm that is not one of the three.</summary>
    [Fact]
    public void ADefaultHmacKey_ForAnUnknownAlgorithm_IsRefused()
        => Assert.Throws<ArgumentException>(() => JsonWebKeyFactory.CreateHmac(SigningAlgorithms.RS256));

    /// <summary>An explicit size is taken as given.</summary>
    [Fact]
    public void AnHmacKeyOfAnExplicitSize_HasThatSize()
        => Assert.Equal(40, JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256, 40).KeyValue!.Length);
}
