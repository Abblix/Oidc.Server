// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses at startup the custodian's keys named for the whole server, which the server never reads: each tenant
/// names keys of its own there.
/// </summary>
/// <remarks>
/// Left in place, they would read as the keys every tenant signs with while each signs with its own. Whether they
/// are registered is asked of the container without building them, since a factory building them may read the very
/// settings this check judges.
/// </remarks>
/// <param name="serviceProvider">The finished container.</param>
internal sealed class ServerWideCustodianKeysValidator(IServiceProvider serviceProvider) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => serviceProvider.GetService<IServiceProviderIsService>()?.IsService(typeof(CustodianHeldKeys)) == true
            ? ValidateOptionsResult.Fail(
                "The custodian's keys named for the whole server are not used: each tenant names its own in " +
                $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.CustodianKeys)}, so leave them out and keep " +
                "the custodian with UseKeysInCustodian() alone.")
            : ValidateOptionsResult.Success;
}
