// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using Abblix.Oidc.Server.Common.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Core = Abblix.Oidc.Server.Model;
using JsonOptions = Microsoft.AspNetCore.Http.Json.JsonOptions;

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// The client metadata a registration or update request carries in its body, or the answer the request gets when
/// the body cannot be read.
/// </summary>
/// <remarks>
/// The framework answers a JSON body it cannot read with a bare 400 before any endpoint filter runs, so the body is
/// read here, through the host's JSON options, and an unreadable document is answered as
/// <see cref="ErrorFactory.UnreadableClientMetadata"/>, as the MVC host answers it. A body of another media type never
/// gets here, since the route accepts JSON only, but one declaring no media type does and is answered 415 as the
/// framework answers it. A body past the size bound keeps the status the server gives it.
/// </remarks>
/// <param name="Request">The metadata read from the body, or <c>null</c> when it could not be read.</param>
/// <param name="Refusal">The answer to a body that could not be read, or <c>null</c> when it was read.</param>
internal sealed record ClientMetadataBody(Core.ClientRegistrationRequest? Request, IResult? Refusal)
{
    private static readonly ClientMetadataBody Unreadable =
        new(null, ErrorFactory.UnreadableClientMetadata.Format(StatusCodes.Status400BadRequest));

    /// <summary>Reads the client metadata from the request body.</summary>
    /// <param name="context">The request whose body is read.</param>
    public static async ValueTask<ClientMetadataBody> BindAsync(HttpContext context)
    {
        if (!context.Request.HasJsonContentType())
            return new ClientMetadataBody(null, Results.StatusCode(StatusCodes.Status415UnsupportedMediaType));

        var options = context.RequestServices.GetRequiredService<IOptions<JsonOptions>>().Value.SerializerOptions;
        try
        {
            var request = await context.Request.ReadFromJsonAsync<Core.ClientRegistrationRequest>(
                options, context.RequestAborted);

            return request is null ? Unreadable : new ClientMetadataBody(request, null);
        }
        catch (JsonException)
        {
            return Unreadable;
        }
        catch (BadHttpRequestException exception)
        {
            return new ClientMetadataBody(null, Results.StatusCode(exception.StatusCode));
        }
    }
}
