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
/// Refuses at startup a tenant that, with its keys coming from its settings, declares no key to sign with, or none
/// to encrypt a service token the server's settings ask to encrypt.
/// </summary>
/// <remarks>
/// The same refusals a server without tenants meets for its own settings, for each tenant: under multi-tenancy the
/// server's own settings carry no keys, so the checks of those settings leave the keys to this one.
/// </remarks>
/// <param name="serviceProvider">The container the key provider is resolved from, once the settings are built.</param>
/// <param name="options">The server's own settings, holding which service tokens are encrypted.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeysValidator(IServiceProvider serviceProvider, IOptions<OidcOptions> options)
    : IValidateOptions<MultiTenancyOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, MultiTenancyOptions tenants)
    {
        if (!SigningKeysPresenceValidator.KeysComeFromSettings(serviceProvider))
            return ValidateOptionsResult.Success;

        ServiceTokensOptions serviceTokens;
        try
        {
            serviceTokens = options.Value.ServiceTokens;
        }
        catch (OptionsValidationException)
        {
            // The server's settings report their own refusal; thrown from here it would replace the tenant list's
            return ValidateOptionsResult.Skip;
        }

        var encrypted = ServiceTokensAlgorithmsValidator.EncryptedTokens(serviceTokens).ToArray();
        var failures = (
            from tenant in tenants.Tenants
            from failure in Failures(tenant, encrypted)
            select $"Tenant '{tenant.Id}': {failure}"
        ).ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static IEnumerable<string> Failures(TenantDefinition tenant, string[] encrypted)
    {
        if (tenant.SigningKeys.Count == 0)
            yield return SigningKeysPresenceValidator.NoSigningKey;

        if (tenant.EncryptionKeys.Count == 0)
        {
            foreach (var tokenType in encrypted)
                yield return ServiceTokensAlgorithmsValidator.NoEncryptionKey(tokenType);
        }
    }
}
