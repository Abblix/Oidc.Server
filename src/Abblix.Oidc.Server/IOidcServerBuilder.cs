// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server;

/// <summary>
/// What registering the server returns, so a feature built on top of it is turned on after it, by a call on this
/// builder rather than on the service collection.
/// </summary>
public interface IOidcServerBuilder
{
    /// <summary>
    /// The services the server was registered in.
    /// </summary>
    IServiceCollection Services { get; }
}
