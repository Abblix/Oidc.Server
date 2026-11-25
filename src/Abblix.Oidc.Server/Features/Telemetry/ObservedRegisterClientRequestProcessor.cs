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
/// The registration endpoint's span names the client the registration stored.
/// </remarks>
internal sealed partial class ObservedRegisterClientRequestProcessor
{
    private partial string? ClientOf(Result<ClientRegistrationSuccessResponse, OidcError> result)
        => StageObservation.ClientOf(result, response => response.ClientId);
}
