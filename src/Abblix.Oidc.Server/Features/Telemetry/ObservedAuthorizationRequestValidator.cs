// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The authorization endpoint's span names the client a valid request is made by.
/// </remarks>
internal sealed partial class ObservedAuthorizationRequestValidator
{
    private partial string? ClientOf(Result<ValidAuthorizationRequest, AuthorizationRequestValidationError> result)
        => StageObservation.ClientOf(result, request => request.ClientInfo.ClientId);
}
