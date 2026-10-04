// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Every scope and resource a request asks for counts as consented, so the authorization endpoint issues a code
/// without a consent page.
/// </summary>
internal sealed class EverythingConsented : IUserConsentsProvider
{
    public Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
        => Task.FromResult(new UserConsents
        {
            Granted = new ConsentDefinition(
                (request.Model.Scope ?? []).Select(scope => new ScopeDefinition(scope)).ToArray(),
                (request.Model.Resources ?? []).Select(uri => new ResourceDefinition(uri)).ToArray()),
            Pending = new ConsentDefinition([], []),
        });
}
