// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Pairwise-faithful test claims provider: returns the same fixed identity as the default test stub but runs the
/// subject through <see cref="ISubjectTypeConverter"/> for the requesting client, exactly as the production
/// <c>UserClaimsProvider</c> does. This makes the id_token carry the real pairwise pseudonym in <c>sub</c>, so an
/// E2E can assert the access token's <c>sub</c> equals the id_token's <c>sub</c> directly rather than against a
/// recomputed value. The default stub emits the raw subject, which cannot exercise that equality.
/// </summary>
public sealed class PairwiseStaticUserClaimsProvider(ISubjectTypeConverter subjectTypeConverter) : IUserClaimsProvider
{
    public Task<JsonObject?> GetUserClaimsAsync(
        AuthSession authSession,
        ICollection<string> scope,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims,
        ClientInfo clientInfo)
    {
        var claims = new JsonObject
        {
            // Mirror UserClaimsProvider: the client-facing subject is the pairwise pseudonym for a pairwise client
            // (a public client is untouched by the converter), so the id_token carries the same value the access
            // token does.
            ["sub"] = subjectTypeConverter.Convert(authSession.Subject, clientInfo),
            ["name"] = "E2E Test User",
            ["email"] = "e2e@example.com",
        };
        return Task.FromResult<JsonObject?>(claims);
    }
}
