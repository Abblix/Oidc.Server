// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the <c>offline_access</c> registration parameter, a server extension to RFC 7591 metadata: a client
/// registering itself may ask for the offline access the host grants new clients
/// (<see cref="NewClientOptions.OfflineAccess"/>) or for less, never for more.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0, section 11, waives <c>prompt=consent</c> only where "other conditions for processing the
/// request permitting offline access" are in place, and stating those conditions for a client is the host's call,
/// never the client's own. An update (RFC 7592 section 2.2) sends back the metadata the server returned, so a client
/// the host already gave more than it grants new clients keeps it there, while one it did not cannot raise itself.
/// </remarks>
/// <param name="options">The server's settings, whose <see cref="NewClientOptions.OfflineAccess"/> is the offline
/// access the host grants new clients, read at each request.</param>
public class OfflineAccessValidator(IOptionsMonitor<OidcOptions> options) : IClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when the client asks for more offline access than the host
    /// grants new clients and it does not already have, or states a value the enumeration does not define;
    /// <c>null</c> otherwise, a request stating none included.
    /// </summary>
    public Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
        => Task.FromResult(Validate(context));

    private OidcError? Validate(ClientRegistrationValidationContext context)
    {
        // A client stating none is registered with what the host grants
        if (context.Request.StatedOfflineAccess is not { } asked)
            return null;

        // A number, or a list of names, that reads into none of the named values
        if (!Enum.IsDefined(asked))
            return ErrorFactory.InvalidClientMetadata($"The {Parameters.OfflineAccess} value is not recognized");

        if (options.CurrentValue.NewClientOptions.OfflineAccess.Covers(asked) || AlreadyHas(context, asked))
            return null;

        return ErrorFactory.InvalidClientMetadata(
            $"The server does not grant the {Parameters.OfflineAccess} value {asked} to a client registering itself");
    }

    /// <summary>
    /// Whether the request updates a client the host has already given the offline access it asks for.
    /// </summary>
    private static bool AlreadyHas(ClientRegistrationValidationContext context, OfflineAccess asked)
    {
        switch (context.Operation)
        {
            case DynamicClientOperation.Register:
                return false;

            case DynamicClientOperation.Update:
                var stored = context.StoredClient ?? throw new InvalidOperationException(
                    $"An update is judged without the {nameof(context.StoredClient)} it replaces");
                return stored.OfflineAccess.Covers(asked);

            default:
                throw new InvalidOperationException($"Unsupported dynamic client operation: {context.Operation}");
        }
    }
}
