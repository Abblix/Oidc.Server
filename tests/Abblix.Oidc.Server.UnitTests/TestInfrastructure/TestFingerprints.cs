// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// One fingerprint source for every test, so a test that asks which fingerprint a record carries asks the same source
/// the component under test wrote it with.
/// </summary>
internal static class TestFingerprints
{
    public static CredentialFingerprints Instance { get; } = new(Options.Create(new OidcOptions()));
}
