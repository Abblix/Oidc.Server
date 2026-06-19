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

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SecurityProfileValidator"/> verifying the fail-loud rejection of a
/// registration whose response types cannot satisfy its effective FAPI 2.0 profile, and the no-op
/// behaviour when no profile applies.
/// </summary>
public class SecurityProfileValidatorTests
{
    private static SecurityProfileValidator CreateValidator() => new();

    private static ClientRegistrationValidationContext CreateContext(
        string[][] responseTypes,
        string? securityProfile = null)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = responseTypes,
            SecurityProfile = securityProfile,
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// A FAPI 2.0 registration limited to the authorization-code response type is self-consistent.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2CodeOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.Code]], ClientSecurityProfiles.Fapi2);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// A FAPI 2.0 registration that requests an implicit response type and never permits code is
    /// rejected with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2ImplicitOnly_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.IdToken]], ClientSecurityProfiles.Fapi2);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// A FAPI 2.0 registration that allows code but also a hybrid response type is rejected: the
    /// hybrid type can never be used under the profile.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2CodePlusHybrid_ShouldReturnError()
    {
        var context = CreateContext(
            [[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]],
            ClientSecurityProfiles.Fapi2);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Without a profile the validator is a no-op: an implicit-only registration passes this step
    /// (the response-type/grant-type consistency is enforced by other validators).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoProfileImplicitOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.IdToken]]);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// A registration that explicitly selects <c>none</c> is not constrained, even with an
    /// implicit-only response type.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ExplicitNoneImplicitOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.IdToken]], ClientSecurityProfiles.None);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.Null(result);
    }
}
