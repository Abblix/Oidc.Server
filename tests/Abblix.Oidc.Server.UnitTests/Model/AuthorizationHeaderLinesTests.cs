// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Model;

/// <summary>
/// The credentials a request carries are read from its Authorization field only when the field arrives on one line:
/// the field is not a list (RFC 9110 sections 11.6.2 and 5.3), so more than one line names no credentials and is
/// reported as such for the endpoint to refuse.
/// </summary>
public class AuthorizationHeaderLinesTests
{
    [Fact]
    public void One_well_formed_line_is_the_credentials()
    {
        var request = new ClientRequest { AuthorizationHeaderLines = [$"{TokenTypes.Bearer} some-token"] };

        Assert.Equal(TokenTypes.Bearer, request.AuthorizationHeader?.Scheme);
        Assert.Equal("some-token", request.AuthorizationHeader?.Parameter);
        Assert.False(request.HasMoreThanOneAuthorizationHeader);
    }

    /// <summary>
    /// What the credentials grammar rejects is narrower than it looks: a scheme is any token, so a phrase parses as
    /// a scheme with the rest as its parameter. What fails is an empty value, or a first token that is not a token.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("=bad")]
    [InlineData("Bearer,token")]
    public void One_line_the_grammar_rejects_names_no_credentials(string line)
    {
        var request = new ClientRequest { AuthorizationHeaderLines = [line] };

        Assert.Null(request.AuthorizationHeader);
        Assert.False(request.HasMoreThanOneAuthorizationHeader);
    }

    [Fact]
    public void No_line_names_no_credentials()
    {
        var request = new ClientRequest();

        Assert.Null(request.AuthorizationHeader);
        Assert.False(request.HasMoreThanOneAuthorizationHeader);
    }

    [Fact]
    public void Two_lines_name_no_credentials_and_are_reported()
    {
        var request = new ClientRequest
        {
            AuthorizationHeaderLines = [$"{TokenTypes.Bearer} some-token", $"{TokenTypes.DPoP} some-token"],
        };

        Assert.Null(request.AuthorizationHeader);
        Assert.True(request.HasMoreThanOneAuthorizationHeader);
    }

    [Fact]
    public void A_registration_request_reads_its_lines_the_same_way()
    {
        var one = new ClientRegistrationRequest { AuthorizationHeaderLines = [$"{TokenTypes.Bearer} some-token"] };
        var two = new ClientRegistrationRequest
        {
            AuthorizationHeaderLines = [$"{TokenTypes.Bearer} a", $"{TokenTypes.Bearer} b"],
        };

        Assert.Equal("some-token", one.AuthorizationHeader?.Parameter);
        Assert.False(one.HasMoreThanOneAuthorizationHeader);
        Assert.Null(two.AuthorizationHeader);
        Assert.True(two.HasMoreThanOneAuthorizationHeader);
    }
}
