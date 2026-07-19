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

using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Locks <see cref="SupportedGrantTypeValidator"/> against the registration-time gap it
/// closes: client registration must surface <c>invalid_client_metadata</c> when
/// <c>grant_types</c> include grants the server doesn't support — including the
/// <c>implicit</c> grant when <c>EnableImplicitFlow()</c> hasn't been called.
/// </summary>
public class SupportedGrantTypeValidatorTests
{
    private static IGrantTypeInformer Informer(params string[] grantTypes) =>
        Mock.Of<IGrantTypeInformer>(i => i.GrantTypesSupported == (IEnumerable<string>)grantTypes);

    private static SupportedGrantTypeValidator Validator(params string[] supportedGrantTypes)
        => new([Informer(supportedGrantTypes)]);

    private static ClientRegistrationValidationContext Context(string[] grantTypes)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            GrantTypes = grantTypes,
        };
        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// Default server (only Authorization Code Flow) accepts the default
    /// <c>authorization_code</c> grant.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_DefaultServer_AcceptsAuthorizationCodeGrant()
    {
        var validator = Validator(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken);

        var result = await validator.ValidateAsync(Context([GrantTypes.AuthorizationCode]));

        Assert.Null(result);
    }

    /// <summary>
    /// Without <c>EnableImplicitFlow()</c> no informer advertises <c>implicit</c> — a client
    /// registering it must be rejected at registration time.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ImplicitFlowDisabled_RejectsImplicitGrant()
    {
        var validator = Validator(GrantTypes.AuthorizationCode);

        var result = await validator.ValidateAsync(Context([GrantTypes.Implicit]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
    }

    /// <summary>
    /// With <c>EnableImplicitFlow()</c> the authorization endpoint contributes
    /// <c>implicit</c>; registration is accepted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ImplicitFlowEnabled_AcceptsImplicitGrant()
    {
        var validator = Validator(GrantTypes.AuthorizationCode, GrantTypes.Implicit);

        var result = await validator.ValidateAsync(Context([GrantTypes.Implicit]));

        Assert.Null(result);
    }

    /// <summary>
    /// Without <c>EnablePasswordGrant()</c> the password grant is absent from the token
    /// endpoint — registration must reject it. Symmetric to the implicit case.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PasswordGrantNotEnabled_RejectsPasswordGrant()
    {
        var validator = Validator(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken);

        var result = await validator.ValidateAsync(Context([GrantTypes.Password]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Password, result.ErrorDescription);
    }

    /// <summary>
    /// When the token endpoint advertises a grant, registering it is accepted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PasswordGrantEnabled_AcceptsPasswordGrant()
    {
        var validator = Validator(GrantTypes.AuthorizationCode, GrantTypes.Password);

        var result = await validator.ValidateAsync(Context([GrantTypes.Password]));

        Assert.Null(result);
    }

    /// <summary>
    /// The validator unions multiple <see cref="IGrantTypeInformer"/> contributions — exactly
    /// the aggregate the discovery endpoint exposes. Implicit can come from one informer,
    /// authorization_code from another, and both register cleanly.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MultipleInformers_UnionedAndAccepted()
    {
        var validator = new SupportedGrantTypeValidator([
            Informer(GrantTypes.Implicit),
            Informer(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken),
        ]);

        var result = await validator.ValidateAsync(
            Context([GrantTypes.AuthorizationCode, GrantTypes.Implicit]));

        Assert.Null(result);
    }

    /// <summary>
    /// A registration request with one supported and one unsupported grant is rejected, and
    /// the error message names the unsupported one.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_MixedGrants_RejectsAndNamesUnsupported()
    {
        var validator = Validator(GrantTypes.AuthorizationCode);

        var result = await validator.ValidateAsync(
            Context([GrantTypes.AuthorizationCode, GrantTypes.Implicit]));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
        Assert.Contains(GrantTypes.Implicit, result.ErrorDescription);
        Assert.DoesNotContain(GrantTypes.AuthorizationCode, result.ErrorDescription);
    }

    /// <summary>
    /// Empty <c>grant_types</c> array — nothing to gate — passes (other validators handle
    /// the «must be specified» rule, this one is purely about server support).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_EmptyGrantTypes_Passes()
    {
        var validator = Validator(GrantTypes.AuthorizationCode);

        var result = await validator.ValidateAsync(Context([]));

        Assert.Null(result);
    }
}
