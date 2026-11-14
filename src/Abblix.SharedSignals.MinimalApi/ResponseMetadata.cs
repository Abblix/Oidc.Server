// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Net.Mime;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Declares the statuses each route answers, for the API description a client is generated from.
/// </summary>
internal static class ResponseMetadata
{
    /// <summary>
    /// Records the statuses a route answers, so a client generated from this surface has a branch for
    /// every answer it can meet and none for an answer it cannot.
    /// </summary>
    /// <remarks>
    /// Bodiless on purpose: the Stream Management API defines no error body - SSF 1.0 Section 8.1 gives
    /// its outcomes as status codes and nothing else. <see cref="AnswersWithBody{TBody}"/> is for the
    /// successes that do carry one.
    /// <para>
    /// A refusal says something beyond its status exactly when it is built as a
    /// <see cref="ChallengeResult"/>, which carries a <c>WWW-Authenticate</c> line naming the reason.
    /// Three places build one: <see cref="BearerChallenges.Unauthenticated"/>,
    /// <see cref="ScopeRequirement.EnforceScopeAsync"/> and
    /// <see cref="BearerChallenges.MissingRequiredParameter"/>. Everything else is a bare status -
    /// anything rendered by <see cref="StreamManagementHandlers.Render{TBody}"/>, whose
    /// <c>ManagementResult</c> description is dropped there because it exists for the operator's logs
    /// rather than for the wire, and the framework's own refusals besides.
    /// </para>
    /// <para>
    /// Said as a property rather than as a list of codes on purpose: 400 is on BOTH sides of it. The
    /// one for a required parameter that names nothing is a challenge, and the one for a delivery
    /// method this transmitter cannot serve is bare, so any enumeration by status code is wrong about
    /// one of them whichever side it puts 400 on.
    /// </para>
    /// </remarks>
    internal static void Answers<TBuilder>(this TBuilder builder, params int[] statusCodes)
        where TBuilder : IEndpointConventionBuilder
    {
        foreach (var statusCode in statusCodes)
        {
            // typeof(void), not the parameterless form. A response type whose Type is null is
            // DISCARDED by the API description pipeline every OpenAPI generator reads, and the
            // operation then falls back to an inferred 200 - so the declaration reaches the endpoint,
            // reads correct at the call site, and publishes nothing. void is how the framework's own
            // Produces(int) says "this status carries no body".
            builder.WithMetadata(new ProducesResponseTypeMetadata(statusCode, typeof(void)));
        }
    }

    /// <summary>
    /// Records a status whose response carries a body, and the type of that body.
    /// </summary>
    internal static RouteHandlerBuilder AnswersWithBody<TBody>(
        this RouteHandlerBuilder builder, int statusCode)
    {
        builder.WithMetadata(new ProducesResponseTypeMetadata(
            statusCode, typeof(TBody), [MediaTypeNames.Application.Json]));
        return builder;
    }
}
