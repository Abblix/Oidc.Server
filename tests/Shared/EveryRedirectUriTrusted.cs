// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Tests.Shared;

/// <summary>
/// Trusts the redirect URIs of every client, for a test host that registers its clients openly and asks for the error
/// responses those clients would be sent: the server's default keeps them at the server for such a client.
/// </summary>
public sealed class EveryRedirectUriTrusted : IRedirectUriTrustPolicy
{
    /// <summary>
    /// Puts this policy in place of the one the server registered, whichever registration came first.
    /// </summary>
    public static void Register(IServiceCollection services)
        => services.Replace(ServiceDescriptor.Singleton<IRedirectUriTrustPolicy, EveryRedirectUriTrusted>());

    /// <inheritdoc />
    public Task<bool> IsTrustedAsync(TenantDefinition tenant, ClientInfo client) => Task.FromResult(true);
}
