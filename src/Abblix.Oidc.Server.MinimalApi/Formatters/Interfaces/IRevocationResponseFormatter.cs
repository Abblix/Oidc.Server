// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using RevocationRequest = Abblix.Oidc.Server.Model.RevocationRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of a token revocation request into an <see cref="IResult"/>.</summary>
public interface IRevocationResponseFormatter
{
    /// <summary>Formats the revocation result (empty 200 on success, OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(RevocationRequest request, Result<TokenRevoked, OidcError> response);
}
