// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Validates that every statically-configured client whose effective profile mandates a control
/// bundle has a configuration that can satisfy it, failing loudly the first time
/// <see cref="OidcOptions"/> is resolved rather than letting a contradiction surface as a per-request
/// rejection at runtime. A no-op for deployments that select no profile, so existing configurations
/// are unaffected.
/// </summary>
public class OidcOptionsSecurityProfileValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = new List<string>();

        // A profile that removes a control without the controls that replace it is a defect in this
        // library rather than in the host's configuration, so it is checked here, where startup can
        // still refuse, instead of being left to whoever reviews the next profile.
        failures.AddRange(SecurityProfileRequirements.FindUnreplacedRelaxations());

        foreach (var client in options.Clients)
        {
            var effectiveProfile = client.SecurityProfile ?? options.DefaultSecurityProfile;

            foreach (var violation in
                     SecurityProfileConsistency.FindViolations(
                         client.EffectiveResponseTypes,
                         client.TokenEndpointAuthMethod,
                         effectiveProfile))
            {
                failures.Add($"Client '{client.ClientId}': {violation}.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
