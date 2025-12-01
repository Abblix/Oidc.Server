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

using System.ComponentModel.DataAnnotations;
using Abblix.Oidc.Server.Mvc.Model;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Model;

/// <summary>
/// Tests for the RequiredWhenNoIdTokenHint validation attribute on EndSessionRequest.
/// Per OIDC RP-Initiated Logout 1.0 specification, client_id is OPTIONAL but required when:
/// - post_logout_redirect_uri is specified AND
/// - id_token_hint is NOT provided
/// </summary>
public class EndSessionRequestValidationTests
{
    /// <summary>
    /// Validates a model using data annotations
    /// </summary>
    private static List<ValidationResult> ValidateModel(object model)
    {
        var validationResults = new List<ValidationResult>();
        var validationContext = new ValidationContext(model, null, null);
        Validator.TryValidateObject(model, validationContext, validationResults, validateAllProperties: true);
        return validationResults;
    }

    [Fact]
    public void ClientId_NotRequired_WhenIdTokenHintProvided()
    {
        // Arrange: Both id_token_hint and post_logout_redirect_uri are provided, client_id is omitted
        var request = new EndSessionRequest
        {
            IdTokenHint = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkRCNjNEQjgwQjlGRjUyRTU5MTY0MkY2ODgzMEE4M0FBQzVBNEI5QTQ3QkI4Q0E1RTc0NzI1QjgxNzA2NkM0QUMiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            PostLogoutRedirectUri = new Uri("https://localhost:5002/signout-callback-oidc"),
            ClientId = null // Should NOT be required
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: No validation errors expected
        Assert.Empty(validationResults);
    }

    [Fact]
    public void ClientId_Required_WhenPostLogoutRedirectUriProvidedWithoutIdTokenHint()
    {
        // Arrange: post_logout_redirect_uri provided without id_token_hint
        var request = new EndSessionRequest
        {
            IdTokenHint = null, // Not provided
            PostLogoutRedirectUri = new Uri("https://localhost:5002/signout-callback-oidc"),
            ClientId = null // Should be REQUIRED in this case
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: Should have validation error for ClientId
        Assert.NotEmpty(validationResults);
        var clientIdError = validationResults.FirstOrDefault(v => v.MemberNames.Contains(nameof(EndSessionRequest.ClientId)));
        Assert.NotNull(clientIdError);
    }

    [Fact]
    public void ClientId_NotRequired_WhenOnlyIdTokenHintProvided()
    {
        // Arrange: Only id_token_hint provided, no post_logout_redirect_uri
        var request = new EndSessionRequest
        {
            IdTokenHint = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkRCNjNEQjgwQjlGRjUyRTU5MTY0MkY2ODgzMEE4M0FBQzVBNEI5QTQ3QkI4Q0E1RTc0NzI1QjgxNzA2NkM0QUMiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            PostLogoutRedirectUri = null,
            ClientId = null // Should NOT be required
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: No validation errors expected
        Assert.Empty(validationResults);
    }

    [Fact]
    public void ClientId_NotRequired_WhenNeitherIdTokenHintNorPostLogoutRedirectUriProvided()
    {
        // Arrange: Neither id_token_hint nor post_logout_redirect_uri provided (session-based logout)
        var request = new EndSessionRequest
        {
            IdTokenHint = null,
            PostLogoutRedirectUri = null,
            ClientId = null // Should NOT be required
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: No validation errors expected
        Assert.Empty(validationResults);
    }

    [Fact]
    public void ClientId_Valid_WhenAllParametersProvided()
    {
        // Arrange: All parameters provided (valid scenario)
        var request = new EndSessionRequest
        {
            IdTokenHint = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkRCNjNEQjgwQjlGRjUyRTU5MTY0MkY2ODgzMEE4M0FBQzVBNEI5QTQ3QkI4Q0E1RTc0NzI1QjgxNzA2NkM0QUMiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            PostLogoutRedirectUri = new Uri("https://localhost:5002/signout-callback-oidc"),
            ClientId = "test_client",
            State = "state_value"
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: No validation errors expected
        Assert.Empty(validationResults);
    }

    [Fact]
    public void ClientId_Valid_WhenProvidedWithPostLogoutRedirectUriButNoIdTokenHint()
    {
        // Arrange: client_id and post_logout_redirect_uri provided, no id_token_hint
        var request = new EndSessionRequest
        {
            IdTokenHint = null,
            PostLogoutRedirectUri = new Uri("https://localhost:5002/signout-callback-oidc"),
            ClientId = "test_client" // Satisfies the requirement
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: No validation errors expected
        Assert.Empty(validationResults);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ClientId_Required_WhenEmptyOrWhitespaceWithPostLogoutRedirectUriButNoIdTokenHint(string emptyClientId)
    {
        // Arrange: Empty/whitespace client_id treated same as null
        var request = new EndSessionRequest
        {
            IdTokenHint = null,
            PostLogoutRedirectUri = new Uri("https://localhost:5002/signout-callback-oidc"),
            ClientId = emptyClientId
        };

        // Act
        var validationResults = ValidateModel(request);

        // Assert: Should have validation error for ClientId
        Assert.NotEmpty(validationResults);
        var clientIdError = validationResults.FirstOrDefault(v => v.MemberNames.Contains(nameof(EndSessionRequest.ClientId)));
        Assert.NotNull(clientIdError);
    }
}
