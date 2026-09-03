// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats a client-removal result (RFC 7592 section 2.3) as <see cref="IResult"/>: an empty 204 on success, or the JSON
/// OAuth error on failure.
/// </summary>
public class RemoveClientResponseFormatter : IRemoveClientResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(ClientRequest request, Result<RemoveClientSuccessfulResponse, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: IResult (_) => Results.NoContent(),
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));
}
