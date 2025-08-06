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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Handles the retrieval of user claims for authentication sessions, ensuring compliance with requested scopes and
/// specific claim details. This class integrates directly with user information providers and scope-to-claim mappings
/// to fetch and validate the necessary user data. It supports converting user data into claims that adhere to
/// OpenID Connect standards, tailored to the specific needs of the client making the request.
/// </summary>
public class UserClaimsProvider : IUserClaimsProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserClaimsProvider"/> class.
    /// </summary>
    /// <param name="logger">The logger used for logging information and errors.</param>
    /// <param name="userInfoProvider">The provider used to retrieve detailed user information based on specific claims.
    /// </param>
    /// <param name="scopeClaimsProvider">The provider that maps requested scopes to the corresponding set of claims.
    /// </param>
    /// <param name="subjectTypeConverter">The converter used to translate user identifiers into subject types as
    /// required by different client configurations.</param>
    public UserClaimsProvider(
        ILogger<UserClaimsProvider> logger,
        IUserInfoProvider userInfoProvider,
        IScopeClaimsProvider scopeClaimsProvider,
        ISubjectTypeConverter subjectTypeConverter)
    {
        _logger = logger;
        _userInfoProvider = userInfoProvider;
        _scopeClaimsProvider = scopeClaimsProvider;
        _subjectTypeConverter = subjectTypeConverter;
    }

    private readonly ILogger _logger;
    private readonly IScopeClaimsProvider _scopeClaimsProvider;
    private readonly IUserInfoProvider _userInfoProvider;
    private readonly ISubjectTypeConverter _subjectTypeConverter;

    /// <summary>
    /// Asynchronously retrieves structured user claims based on an authentication session and specific claim parameters.
    /// This method ensures compliance with the OpenID Connect standards by validating essential claims and formatting
    /// the user data into a structured JSON object.
    /// </summary>
    /// <param name="authSession">The authentication session providing the context for user claims retrieval.</param>
    /// <param name="scope">A collection of scopes defining the categories of claims required.</param>
    /// <param name="requestedClaims">A collection detailing specific claims requested by the client, including any
    /// requirements for essential claims.</param>
    /// <param name="clientInfo">Information about the client application making the request, which may influence how
    /// claims are processed and returned.</param>
    /// <returns>A task that when completed returns a <see cref="JsonObject"/> representing the user claims,
    /// or throws an exception if required claims are missing.</returns>
    public async Task<JsonObject?> GetUserClaimsAsync(
        AuthSession authSession,
        ICollection<string> scope,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims,
        ClientInfo clientInfo)
    {
        var claimNames = _scopeClaimsProvider.GetRequestedClaims(
            scope, requestedClaims?.Select(claim => claim.Key))
            .Distinct(StringComparer.Ordinal);

        var userInfo = await _userInfoProvider.GetUserInfoAsync(authSession.Subject, claimNames);
        if (userInfo == null)
        {
            _logger.LogWarning("The user claims were not found by subject value");
            return null;
        }

        var subject = _subjectTypeConverter.Convert(authSession.Subject, clientInfo);
        userInfo.SetProperty(JwtClaimTypes.Subject, subject);

        if (FindMissingClaims(userInfo, requestedClaims) is { Length: > 0 } missingClaims)
        {
            _logger.LogWarning("The following claims are requested, but not returned from {IUserInfoProvider}: {@MissingClaims}",
                _userInfoProvider.GetType().FullName,
                missingClaims);

            return null;
        }

        return userInfo;
    }

    private static string[]? FindMissingClaims(
        JsonObject userInfo,
        ICollection<KeyValuePair<string, RequestedClaimDetails>>? requestedClaims)
    {
        if (requestedClaims == null)
            return null;

        var missingClaims = (
            from claim in requestedClaims
            where claim.Value.Essential == true && !userInfo.TryGetPropertyValue(claim.Key, out _)
            select claim.Key).ToArray();

        return missingClaims;
    }
}
