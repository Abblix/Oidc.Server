// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// The settings of the one issuer a deployment without multi-tenancy serves, taken from <see cref="OidcOptions"/>.
/// </summary>
internal sealed class OptionsIssuerSettings(IOptions<OidcOptions> options) : IIssuerSettings
{
    /// <inheritdoc />
    public IEnumerable<ClientInfo> Clients => options.Value.Clients;
}
