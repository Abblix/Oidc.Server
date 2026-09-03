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
/// Formats a client-update result (RFC 7592 section 2.2) as <see cref="IResult"/>: a 200 with the updated client
/// configuration on success, or the JSON OAuth error on failure.
/// </summary>
/// <param name="uriBuilder">Builds the <c>registration_client_uri</c> for the client.</param>
public class UpdateClientResponseFormatter(RegistrationClientUriBuilder uriBuilder) : IUpdateClientResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(UpdateClientRequest request, Result<ReadClientSuccessfulResponse, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: IResult (success) => Results.Json(success with
            {
                RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                    ? uriBuilder.Build(success.ClientId)
                    : null,
            }),
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));
}
