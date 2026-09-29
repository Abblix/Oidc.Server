// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup a multi-tenant deployment that also names one issuer for the whole server.
/// </summary>
/// <remarks>
/// Each tenant declares its own issuer in <see cref="TenantDefinition.Issuer"/>, and that is the one every
/// token and discovery document carries, so a configured <see cref="OidcOptions.Issuer"/> would be ignored
/// while reading as if it applied.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantIssuerOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => options.Issuer is null
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions)}.{nameof(OidcOptions.Issuer)} names one issuer for the whole server; " +
                $"under multi-tenancy each tenant declares its own in {nameof(TenantDefinition)}." +
                $"{nameof(TenantDefinition.Issuer)}, so leave it unset.");
}
