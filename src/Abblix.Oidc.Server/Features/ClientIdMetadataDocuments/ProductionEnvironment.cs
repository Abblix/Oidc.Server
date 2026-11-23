// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Whether the host runs in the Production environment, where draft-ietf-oauth-client-id-metadata-document section
/// 10.7 has the server "MUST NOT apply this exception": read once, for the startup refusal and for every lookup alike,
/// so a setting changed after start cannot apply the exception there either.
/// </summary>
/// <remarks>
/// A host built without the generic host registers no <see cref="IHostEnvironment"/>, and is taken for one that is not
/// Production: nothing tells it apart from a development host, and the issuer-on-loopback rule still holds for each
/// tenant.
/// </remarks>
/// <param name="provider">The container the host environment is read from, when it holds one.</param>
internal sealed class ProductionEnvironment(IServiceProvider provider)
{
    /// <summary>
    /// Whether the host's environment is Production.
    /// </summary>
    public bool IsCurrent { get; } = provider.GetService<IHostEnvironment>() is { } environment && environment.IsProduction();
}
