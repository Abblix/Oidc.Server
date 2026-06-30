// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats a client-update result (RFC 7592 §2.2) as <see cref="IResult"/>: a 200 with the updated client
/// configuration on success, or the JSON OAuth error on failure.
/// </summary>
/// <param name="uriBuilder">Builds the <c>registration_client_uri</c> for the client.</param>
public class UpdateClientResultFormatter(RegistrationClientUriBuilder uriBuilder) : IUpdateClientResultFormatter
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
