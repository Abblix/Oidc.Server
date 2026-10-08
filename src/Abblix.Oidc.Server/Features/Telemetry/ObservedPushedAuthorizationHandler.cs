// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The pushed authorization endpoint's span names the request's response type, when the protocol defines each of its
/// values.
/// </remarks>
internal sealed partial class ObservedPushedAuthorizationHandler
{
    private partial (string Key, string? Value) RequestTagOf(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest)
        => (TelemetryTags.ResponseType, EndpointObservation.ResponseTypeOf(authorizationRequest.ResponseType));
}
