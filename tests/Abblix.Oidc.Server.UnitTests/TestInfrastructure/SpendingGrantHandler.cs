// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// A grant handler answered as the token endpoint ends up answering it: a grant the handler authorizes has what it
/// is redeemed with spent, as it is once tokens are issued for it, and a refusal of the spend is the answer.
/// </summary>
/// <param name="inner">The handler under test.</param>
internal sealed class SpendingGrantHandler(IAuthorizationGrantHandler inner) : IAuthorizationGrantHandler
{
    public IEnumerable<string> GrantTypesSupported => inner.GrantTypesSupported;

    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
        TenantDefinition tenant,
        TokenRequest request,
        ClientInfo clientInfo,
        IClientInfoProvider clients,
        CancellationToken cancellationToken)
    {
        var result = await inner.AuthorizeAsync(tenant, request, clientInfo, clients, cancellationToken);

        if (result.TryGetSuccess(out var grant) &&
            grant.Redemption is { } redemption &&
            await redemption.SpendAsync(tenant, clientInfo) is { } refused)
        {
            return refused;
        }

        return result;
    }
}
