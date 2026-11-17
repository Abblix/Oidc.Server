// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// What the login page's post needs from the container to check the user, sign them in and send them on.
/// </summary>
/// <param name="AuthService">Signs the user in.</param>
/// <param name="EndpointResolver">Names the authorization endpoint the user is sent back to.</param>
/// <param name="SessionIdGenerator">Names the new session.</param>
/// <param name="TimeProvider">Stamps when the user signed in.</param>
/// <param name="PendingRequests">Holds the pending authorization request the form carries back.</param>
/// <param name="Clients">Finds the client the pending request is for, shown again on a refused attempt.</param>
/// <param name="ConformanceUser">The one user the suite signs in as.</param>
public sealed record LoginServices(
    IAuthSessionService AuthService,
    IOidcEndpointResolver EndpointResolver,
    ISessionIdGenerator SessionIdGenerator,
    TimeProvider TimeProvider,
    IAuthorizationRequestStorage PendingRequests,
    IClientInfoProvider Clients,
    ConformanceUser ConformanceUser);
