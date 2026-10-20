// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using static Abblix.Oidc.Server.Model.ClientRegistrationRequest;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Validates the <c>offline_access</c> registration parameter, a server extension to RFC 7591 metadata: a client
/// registering itself may ask for no offline access or for offline access with <c>prompt=consent</c>, but not for
/// offline access without it.
/// </summary>
/// <remarks>
/// OpenID Connect Core 1.0, section 11, waives <c>prompt=consent</c> only where "other conditions for processing the
/// request permitting offline access" are in place, and stating those conditions for a client is the host's call,
/// never the client's own.
/// </remarks>
public class OfflineAccessValidator : SyncClientRegistrationContextValidator
{
    /// <summary>
    /// Returns an <c>invalid_client_metadata</c> error when the client asks for offline access without
    /// <c>prompt=consent</c>; <c>null</c> otherwise.
    /// </summary>
    protected override OidcError? Validate(ClientRegistrationValidationContext context)
        => context.Request.OfflineAccess switch
        {
            OfflineAccess.Disabled or OfflineAccess.ConsentRequired => null,
            OfflineAccess.Allowed => ErrorFactory.InvalidClientMetadata(
                $"The {Parameters.OfflineAccess} a client asks for at registration requires prompt=consent"),
            _ => throw new ArgumentOutOfRangeException(
                nameof(context), context.Request.OfflineAccess, $"Unknown {nameof(OfflineAccess)} value"),
        };
}
