// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <remarks>
/// The end-session endpoint's span names the client a valid request names, when it names one.
/// </remarks>
internal sealed partial class ObservedEndSessionRequestValidator
{
    private partial string? ClientOf(Result<ValidEndSessionRequest, OidcError> result)
        => result.TryGetSuccess(out var request) ? request.ClientInfo?.ClientId : null;
}
