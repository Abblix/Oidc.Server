// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a multi-tenant deployment that fixes one issuer for every tenant.
/// </summary>
/// <remarks>
/// A tenant's issuer is its own, so a configured <see cref="OidcOptions.Issuer"/> would give every tenant the
/// same one, and each would accept the tokens of the others.
/// </remarks>
public sealed class TenantIssuerOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => options.Issuer is null
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.Issuer)} names one issuer for every tenant; " +
                "leave it unset under multi-tenancy, where each tenant's issuer is derived from its request.");
}
