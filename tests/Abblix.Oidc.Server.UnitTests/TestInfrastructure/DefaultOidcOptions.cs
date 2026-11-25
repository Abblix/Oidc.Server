// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// The server's options at their defaults, for a test constructing a service that reads them.
/// </summary>
public static class DefaultOidcOptions
{
    /// <summary>
    /// A monitor answering the default options.
    /// </summary>
    public static IOptionsMonitor<OidcOptions> Monitor()
        => Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == new OidcOptions());
}
