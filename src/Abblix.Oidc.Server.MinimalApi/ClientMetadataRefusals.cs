// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Core = Abblix.Oidc.Server.Model;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Refuses a client registration or update whose body cannot be read, by its token first. The registration endpoint
/// requiring an initial access token (RFC 7591 section 3) and the client configuration endpoint (RFC 7592 section 2.2,
/// which answers a token "not valid" as RFC 6750 does) are protected resources, and RFC 6750 section 3 has a request
/// without a token enabling access answered with the WWW-Authenticate field, whatever its body holds.
/// </summary>
internal static class ClientMetadataRefusals
{
    private static IResult UnsupportedMediaType => Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);

    /// <summary>
    /// Answers a registration whose body is of a media type the registration endpoint does not accept: routing answers
    /// one no endpoint accepts with a 415 of its own, before any token is read.
    /// </summary>
    public static Task<IResult> RegisterClientOfAnotherMediaTypeAsync(HttpContext context)
        => RefuseRegistrationAsync(context, UnsupportedMediaType);

    /// <summary>
    /// Answers an update whose body is of a media type the update endpoint does not accept: routing answers one no
    /// endpoint accepts with a 415 of its own, before any token is read.
    /// </summary>
    public static Task<IResult> UpdateClientOfAnotherMediaTypeAsync(
        ClientAuthorizationRequest authorizationRequest, HttpContext context)
        => RefuseUpdateAsync(context, authorizationRequest, UnsupportedMediaType);

    /// <summary>
    /// Refuses the registration by its initial access token where the server requires one and the token does not pass,
    /// and by <paramref name="refusal"/> otherwise.
    /// </summary>
    public static async Task<IResult> RefuseRegistrationAsync(HttpContext context, IResult refusal)
    {
        var services = context.RequestServices;
        var lines = FormValues.HeaderLines(context.Request, HttpRequestHeaders.Authorization);
        var tokenError = await services.GetRequiredService<IInitialAccessTokenValidator>()
            .ValidateAsync(services.GetRequiredService<ITenantAccessor>().CurrentTenant(), lines);

        if (tokenError is null)
            return refusal;

        // The refused body holds no metadata, and a failure is formatted from the error alone
        return await services.GetRequiredService<IRegisterClientResponseFormatter<IResult>>().FormatResponseAsync(
            new Core.ClientRegistrationRequest { AuthorizationHeaderLines = lines }, tokenError);
    }

    /// <summary>
    /// Refuses the update by its registration access token where the token does not pass, and by
    /// <paramref name="refusal"/> otherwise.
    /// </summary>
    public static async Task<IResult> RefuseUpdateAsync(
        HttpContext context, ClientAuthorizationRequest authorizationRequest, IResult refusal)
    {
        var services = context.RequestServices;
        Core.ClientRequest clientRequest = authorizationRequest;
        var validation = await services.GetRequiredService<IClientRequestValidator>()
            .ValidateAsync(services.GetRequiredService<ITenantAccessor>().CurrentTenant(), clientRequest);

        if (!validation.TryGetFailure(out var error))
            return refusal;

        // The refused body holds no metadata, and a failure is formatted from the error alone
        return await services.GetRequiredService<IUpdateClientResponseFormatter<IResult>>().FormatResponseAsync(
            new UpdateClientRequest(clientRequest, new Core.ClientRegistrationRequest()), error);
    }
}
