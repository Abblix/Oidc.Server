// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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

        foreach (var client in options.Clients)
        {
            var effectiveProfile = client.SecurityProfile ?? options.DefaultSecurityProfile;

            foreach (var violation in
                     SecurityProfileConsistency.FindViolations(client.EffectiveResponseTypes, effectiveProfile))
            {
                failures.Add($"Client '{client.ClientId}': {violation}.");
            }
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
