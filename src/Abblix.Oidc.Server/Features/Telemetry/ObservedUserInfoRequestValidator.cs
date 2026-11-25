// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The UserInfo endpoint's span names the client the presented access token was issued to.
/// </remarks>
internal sealed partial class ObservedUserInfoRequestValidator
{
    private partial string? ClientOf(Result<ValidUserInfoRequest, OidcError> result)
        => StageObservation.ClientOf(result, request => request.ClientInfo.ClientId);
}
