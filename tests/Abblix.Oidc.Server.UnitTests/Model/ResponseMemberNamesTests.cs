// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// Every other test reads these responses through the same constants the server writes them with, so a changed
/// constant would pass the whole suite while every client stopped finding the member. These tests hold the names
/// as the specifications and the end-session request spell them, which is why, for these responses, they are
/// literals here and nowhere else.
/// </summary>
public class ResponseMemberNamesTests
{
    [Fact]
    public void ATokenResponseNamesItsMembersAsRfc6749Does()
    {
        var response = new TokenResponse
        {
            AccessToken = "access",
            TokenType = TokenTypes.Bearer,
            IssuedTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
            ExpiresIn = TimeSpan.FromMinutes(5),
            RefreshToken = "refresh",
            Scope = [Scopes.OpenId],
            IdToken = "id",
            AuthorizationDetails = [new JsonObject { [AuthorizationDetail.Parameters.Type] = "payment" }],
        };

        Assert.Equal(
            [
                "access_token", "authorization_details", "expires_in", "id_token", "issued_token_type",
                "refresh_token", "scope", "token_type",
            ],
            MemberNames(response));
    }

    [Fact]
    public void AnErrorResponseNamesItsMembersAsRfc6749Does()
    {
        Assert.Equal(
            ["error", "error_description"],
            MemberNames(new ErrorResponse(ErrorCodes.InvalidRequest, "description")));
    }

    [Fact]
    public void APushedAuthorizationResponseNamesItsMembersAsRfc9126Does()
    {
        var response = new PushedAuthorizationResponse
        {
            RequestUri = new Uri("urn:ietf:params:oauth:request_uri:abc"),
            ExpiresIn = TimeSpan.FromMinutes(1),
        };

        Assert.Equal(["expires_in", "request_uri"], MemberNames(response));
    }

    [Fact]
    public void ALogoutConfirmationAnswerNamesItsMembersAsTheEndSessionRequestReadsThem()
    {
        // The confirmation travels back as the end-session request's own parameter, so the two names are one
        Assert.Equal(EndSessionRequest.Parameters.Confirmation, ConfirmationRequiredResponse.Parameters.Confirmation);
        Assert.Equal(
            ["confirmation", "error", "error_description"],
            MemberNames(new ConfirmationRequiredResponse(ErrorCodes.ConfirmationRequired, "description", "value")));
    }

    private static string[] MemberNames<T>(T response)
        => JsonSerializer.SerializeToNode(response)!.AsObject()
            .Select(member => member.Key)
            .Order(StringComparer.Ordinal)
            .ToArray();
}
