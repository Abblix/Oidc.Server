// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a configured client that may use backchannel authentication without authenticating itself.
/// </summary>
/// <remarks>
/// CIBA Core 1.0 sections 7.1 and 10.1 have the client authenticate at both endpoints of the flow, and both endpoints
/// refuse a client registered with the method "none". Refusing it here as well tells the deployment when it starts,
/// rather than with the first request such a client makes. A tenant's clients are judged by the same check.
/// </remarks>
public sealed class BackChannelClientAuthenticationValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var failures = (
            from client in options.Clients ?? []
            where client is { ClientType: ClientType.Public } && client.EffectiveGrantTypes.Contains(GrantTypes.Ciba)
            select $"Client '{client.ClientId}' may use backchannel authentication but authenticates with " +
                   $"'{client.TokenEndpointAuthMethod}'; the flow requires a client that authenticates itself."
        ).ToList();

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
