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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SecurityProfileValidator"/>. A dynamically registered client cannot
/// declare a profile (that is a server-side policy decision), so the validator rejects a registration
/// whose response types cannot satisfy the server-wide <c>DefaultSecurityProfile</c>, and is a no-op
/// when no server-wide profile applies.
/// </summary>
public class SecurityProfileValidatorTests
{
    private static SecurityProfileValidator CreateValidator(
        ClientSecurityProfile defaultSecurityProfile = ClientSecurityProfile.None)
        => new(Options.Create(new OidcOptions { DefaultSecurityProfile = defaultSecurityProfile }));

    private static ClientRegistrationValidationContext CreateContext(string[][] responseTypes)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = responseTypes,
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// With no server-wide profile the validator is a no-op: an implicit-only registration passes this
    /// step (the response-type/grant-type consistency is enforced by other validators).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoServerProfileImplicitOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.IdToken]]);

        var result = await CreateValidator().ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration limited to the authorization-code response
    /// type is self-consistent.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2CodeOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.Code]]);

        var result = await CreateValidator(ClientSecurityProfile.Fapi2).ValidateAsync(context);

        Assert.Null(result);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration that requests an implicit response type and
    /// never permits code is rejected with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2ImplicitOnly_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.IdToken]]);

        var result = await CreateValidator(ClientSecurityProfile.Fapi2).ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration that allows code but also a hybrid response
    /// type is rejected: the hybrid type can never be used under the profile.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2CodePlusHybrid_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]]);

        var result = await CreateValidator(ClientSecurityProfile.Fapi2).ValidateAsync(context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }
}
