// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

// Spelled out rather than left to ImplicitUsings, because this file is compiled into suites that do not enable it.
using System.Threading.Tasks;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Tests.Shared;

/// <summary>
/// The consent of a test host whose end user grants every client everything it asks for while anybody may register a
/// client: the server does not start with the provider AddConsentGrantedForEveryClient() registers in that case, so the
/// host answers consent as a host's own provider does, with the answer that provider gives.
/// </summary>
public sealed class EveryConsentGiven : IUserConsentsProvider
{
    private readonly NullConsentService _granted = new();

    /// <summary>
    /// Puts this provider in place of any the server or the host registered, whichever registration came first.
    /// </summary>
    public static void Register(IServiceCollection services)
        => services.Replace(ServiceDescriptor.Singleton<IUserConsentsProvider, EveryConsentGiven>());

    /// <inheritdoc />
    public Task<UserConsents> GetUserConsentsAsync(
        TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
        => _granted.GetUserConsentsAsync(tenant, request, authSession);
}
