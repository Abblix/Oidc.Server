// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The client configuration endpoint's span names the client its registration access token manages.
/// </remarks>
internal sealed partial class ObservedUpdateClientRequestValidator
{
    private partial string? ClientOf(Result<ValidUpdateClientRequest, OidcError> result)
        => StageObservation.ClientOf(result, request => request.Client.ClientInfo.ClientId);
}
