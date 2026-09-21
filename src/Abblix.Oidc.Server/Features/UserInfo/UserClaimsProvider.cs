// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Handles the retrieval of user claims for authentication sessions, from the scopes the request carries and the
/// individual claims it names. This class integrates directly with user information providers and scope-to-claim
/// mappings to fetch the user data, and converts it into claims that adhere to OpenID Connect standards, tailored
/// to the specific needs of the client making the request.
/// </summary>
/// <param name="logger">The logger used for logging information and errors.</param>
/// <param name="userInfoProvider">The provider used to retrieve detailed user information based on specific claims.
/// </param>
/// <param name="scopeClaimsProvider">The provider that maps requested scopes to the corresponding set of claims.
/// </param>
/// <param name="subjectTypeConverter">The converter used to translate user identifiers into subject types as
/// required by different client configurations.</param>
public partial class UserClaimsProvider(
    ILogger<UserClaimsProvider> logger,
    IUserInfoProvider userInfoProvider,
    IScopeClaimsProvider scopeClaimsProvider,
    ISubjectTypeConverter subjectTypeConverter) : IUserClaimsProvider
{
    /// <summary>
    /// Asynchronously retrieves structured user claims based on an authentication session and specific claim parameters.
    /// A claim the host's provider does not hold is absent from the result rather than a reason to refuse it: OpenID
    /// Connect Core 1.0 section 5.5.1 forbids answering with an error when claims are not returned, essential or
    /// voluntary alike, unless the description of the specific claim says otherwise.
    /// </summary>
    /// <param name="authSession">The authentication session providing the context for user claims retrieval.</param>
    /// <param name="scope">A collection of scopes defining the categories of claims required.</param>
    /// <param name="requestedClaims">The individual claims the client named. Their names widen what is asked of
    /// the host's provider; whether the client called one essential decides nothing here, except for
    /// <c>acr</c>.</param>
    /// <param name="clientInfo">Information about the client application making the request, which may influence how
    /// claims are processed and returned.</param>
    /// <returns>A task that when completed returns a <see cref="JsonObject"/> representing the user claims,
    /// or null when the host's provider knows no such user.</returns>
    public async Task<JsonObject?> GetUserClaimsAsync(
        AuthSession authSession,
        ICollection<string> scope,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims,
        ClientInfo clientInfo)
    {
        var claimNames = scopeClaimsProvider.GetRequestedClaims(
            scope, requestedClaims?.Select(claim => claim.Key))
            .Distinct(StringComparer.Ordinal);

        var userInfo = await userInfoProvider.GetUserInfoAsync(authSession, claimNames);
        if (userInfo == null)
        {
            LogUserClaimsNotFound();
            return null;
        }

        // The one claim whose own description imposes a condition, which is what section 5.5.1 exempts from
        // the rule above: section 5.5.1.1 requires an acr matching one of the requested values, and says the
        // server "MUST treat that outcome as a failed authentication attempt" when the requirement cannot be
        // met. Nothing evaluates those values yet, and the identity token writes acr from the session
        // whatever this returns, so answering would assert an authentication level the request declared
        // unacceptable. Withholding is not the failed attempt the section asks for; it is what keeps the
        // server from asserting something false until the comparison exists.
        if (requestedClaims != null &&
            requestedClaims.Any(claim => claim is { Key: JwtClaimTypes.AuthContextClassRef, Value.Essential: true }))
        {
            return null;
        }

        var subject = subjectTypeConverter.Convert(authSession.Subject, clientInfo);
        userInfo.SetProperty(JwtClaimTypes.Subject, subject);

        return userInfo;
    }
}
