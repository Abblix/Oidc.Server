// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Default implementation of IAcrMetadataProvider that reads ACR values from OidcOptions configuration.
/// </summary>
public sealed class AcrMetadataProvider(IOptionsSnapshot<OidcOptions> options) : IAcrMetadataProvider
{
	/// <inheritdoc />
	public IEnumerable<string>? AcrValuesSupported => options.Value.Discovery.AcrValuesSupported;
}
