// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Key material for tests that choose a key but never sign with it: enough for the key to be chosen, nothing more.
/// </summary>
public static class TestKeyMaterial
{
    /// <summary>
    /// A 2048-bit modulus, the smallest RFC 7518 sections 3.3 and 3.5 let an RSA key sign with, so a key carrying it
    /// is chosen for an RSA signature algorithm.
    /// </summary>
    public static byte[] Rsa2048Modulus { get; } = [0x80, .. Enumerable.Repeat((byte)0x01, 255)];
}
