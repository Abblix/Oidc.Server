// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The token endpoint's span names the request's grant type, when the server supports it as spelled.
/// </summary>
internal sealed partial class ObservedTokenHandler
{
    private partial (string Key, string? Value) RequestTagOf(
        TokenRequest tokenRequest,
        ClientRequest clientRequest,
        CancellationToken cancellationToken)
        => (TelemetryTags.GrantType,
            EndpointObservation.GrantTypeOf(tokenRequest.GrantType, _authorizationGrantHandler.GrantTypesSupported));
}
