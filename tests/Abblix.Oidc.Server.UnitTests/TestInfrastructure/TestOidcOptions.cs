// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The server's options as a type built by hand takes them, for tests that construct one directly.
/// </summary>
public static class TestOidcOptions
{
    /// <summary>
    /// The given options, or the defaults when none are given.
    /// </summary>
    public static IOptions<OidcOptions> Defaults(OidcOptions? options = null) => Options.Create(options ?? new OidcOptions());
}
