// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Single source for the in-memory TestServer's base address. Centralised so the
/// Sonar S1075 hardcoded-URI suppression lives in one spot rather than spreading
/// across every factory/test that instantiates an HttpClient. The TestServer is
/// not a deployment surface - its base URL is host-anchored on
/// <c>https://localhost</c> only because the OIDC MVC controllers carry
/// <c>[RequireHttps]</c> and need <c>Request.IsHttps == true</c>.
/// </summary>
public static class TestServerAddress
{
    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "In-memory TestServer base address; not a deployment URL.")]
    public static readonly Uri BaseAddress = new("https://localhost");
}
