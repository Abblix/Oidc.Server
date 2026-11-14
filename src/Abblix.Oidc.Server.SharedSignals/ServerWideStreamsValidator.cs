// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Refuses to start a server holding streams declared for the whole server, which belong to no tenant's receivers.
/// </summary>
/// <remarks>
/// A check of the settings rather than a started service, because it has to come before the started services are
/// built: one of them is built on the stream store, which such streams break outside a tenant as soon as one needs
/// a poll address. It asks the container whether they are registered and builds nothing, so it cannot wait on the
/// settings it checks.
/// </remarks>
/// <param name="services">Tells whether streams are declared for the whole server.</param>
internal sealed class ServerWideStreamsValidator(IServiceProviderIsService services) : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
        => services.IsService(typeof(IReadOnlyList<ConfiguredStream>))
            ? ValidateOptionsResult.Fail(
                "Streams declared for the whole server belong to no tenant's receivers; declare each tenant's with "
                + $"{nameof(SharedSignalsMultiTenancyExtensions.AddConfiguredStreams)}() on what AddOidcServices() "
                + "returns.")
            : ValidateOptionsResult.Success;
}
