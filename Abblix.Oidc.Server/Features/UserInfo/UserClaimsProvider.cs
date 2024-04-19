// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
//
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
//
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
//
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
//
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
//
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
//
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
            scope, requestedClaims?.Select(claim => claim.Key));

        var userInfo = await _userInfoProvider.GetUserInfoAsync(
            authSession.Subject,
            claimNames.Distinct(StringComparer.Ordinal));
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
