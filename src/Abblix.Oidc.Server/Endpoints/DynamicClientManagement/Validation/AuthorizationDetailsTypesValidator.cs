// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Common;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Rejects client registration when the requested <c>authorization_details_types</c> per-client
/// allowlist (RFC 9396 section 10) names any <c>type</c> value the server does not understand,
/// returning <c>invalid_client_metadata</c> per OIDC DCR section 3.2. Without this gate the
/// registration would succeed and every RAR-bearing request from this client would fail at
/// the authorize/PAR endpoint with <c>invalid_authorization_details</c> - a worse error
/// surface for the deployer who registered with a typo.
/// </summary>
/// <remarks>
/// The server-supported set is enumerated from the same keyed-DI registry of
/// <see cref="IAuthorizationDetailValidator"/> implementations that request-time dispatch
/// uses, via <see cref="KeyedService.AnyKey"/>. This makes registration gating, run-time
/// gating, and discovery's <c>authorization_details_types_supported</c> field share one
/// source of truth - same shape as <see cref="SupportedGrantTypeValidator"/>.
///
/// Semantics of the requested allowlist:
/// - <c>null</c> - client does not request any constraint; this validator passes.
/// - Empty array - client explicitly opts out of RAR; passes (a client may legitimately
///   register zero allowed types to disable the feature for itself).
/// - Non-empty array - every value must appear in the server-supported set, else reject.
/// </remarks>
public class AuthorizationDetailsTypesValidator(
    IServiceProvider serviceProvider) : SyncClientRegistrationContextValidator
{
    /// <inheritdoc />
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
    {
        var requested = context.Request.AuthorizationDetailsTypes;
        if (requested is null || requested.Length == 0)
            return null;

        var supported = serviceProvider
            .GetKeyedServices<IAuthorizationDetailValidator>(KeyedService.AnyKey)
            .Select(v => v.Type)
            .ToHashSet(StringComparer.Ordinal);

        var unsupported = requested
            .Where(t => !supported.Contains(t))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (unsupported.Length == 0)
            return null;

        return ErrorFactory.InvalidClientMetadata(
            $"The following authorization_details types are not supported by this server: {string.Join(", ", unsupported)}");
    }
}
