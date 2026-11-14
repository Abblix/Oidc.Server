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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// A validator of payment initiation entries that accepts an entry only when asked at the tenant the tests serve, so
/// a caller asking it at another tenant is refused.
/// </summary>
internal sealed class ServedTenantOnlyValidator : IAuthorizationDetailValidator
{
    /// <summary>The type it validates.</summary>
    public const string PaymentType = "payment_initiation";

    public string Type => PaymentType;

    public Task<Result<AuthorizationDetail, OidcError>> ValidateAsync(
        TenantDefinition tenant,
        AuthorizationDetail detail,
        ClientInfo client,
        CancellationToken token)
        => Task.FromResult(AtTheServedTenant(tenant, detail));

    public Task<Result<AuthorizationDetail, OidcError>> ValidateGrantedAsync(
        TenantDefinition tenant,
        AuthorizationDetail detail,
        IReadOnlyList<AuthorizationDetail> requested,
        ClientInfo client,
        CancellationToken token)
        => Task.FromResult(AtTheServedTenant(tenant, detail));

    private static Result<AuthorizationDetail, OidcError> AtTheServedTenant(TenantDefinition tenant, AuthorizationDetail detail)
        => tenant.Id == SingleIssuer.Tenant.Id
            ? detail
            : new OidcError(ErrorCodes.InvalidAuthorizationDetails, "asked at a tenant the test does not serve");
}
