// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// The builder registering the server with either transport adapter returns.
/// </summary>
/// <param name="services">The services the server was registered in.</param>
internal sealed class OidcServerBuilder(IServiceCollection services) : IOidcServerBuilder
{
    /// <inheritdoc />
    public IServiceCollection Services => services;
}
