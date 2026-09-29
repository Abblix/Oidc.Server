// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// Services built as a server without tenants builds them: for its one issuer, from <see cref="OidcOptions"/>.
/// </summary>
internal static class SingleIssuer
{
    public static IIssuerSettings Settings => new OptionsIssuerSettings(Options.Create(new OidcOptions()));

    public static ScopeManager ScopeManager(IOptions<OidcOptions> options)
        => new(new OptionsIssuerSettings(options), new SingleIssuerLocal<Dictionary<string, ScopeDefinition>>());

    public static ResourceManager ResourceManager(IOptions<OidcOptions> options)
        => new(new OptionsIssuerSettings(options), new SingleIssuerLocal<Dictionary<Uri, ResourceDefinition>>());
}
