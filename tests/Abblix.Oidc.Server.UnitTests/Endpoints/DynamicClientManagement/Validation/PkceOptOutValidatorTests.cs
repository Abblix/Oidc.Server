// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// RFC 8252 section 8.1: "Authorization servers SHOULD reject authorization requests from native apps that don't use
/// PKCE", so a registration turning PKCE off is refused for a native app and for a client with no credentials.
/// </summary>
public class PkceOptOutValidatorTests
{
    private readonly PkceOptOutValidator _validator = new();

    [Theory]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.None)]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.PrivateKeyJwt)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.None)]
    public async Task TurningPkceOff_ForANativeOrPublicClient_IsRefused(string applicationType, string authMethod)
    {
        var result = await Validate(applicationType, authMethod, pkceRequired: false);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    [Theory]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.ClientSecretBasic, false)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.PrivateKeyJwt, false)]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.None, true)]
    [InlineData(ApplicationTypes.Native, ClientAuthenticationMethods.None, null)]
    [InlineData(ApplicationTypes.Web, ClientAuthenticationMethods.None, null)]
    public async Task AConfidentialWebClient_OrOneKeepingPkce_IsAccepted(
        string applicationType,
        string authMethod,
        bool? pkceRequired)
    {
        Assert.Null(await Validate(applicationType, authMethod, pkceRequired));
    }

    private async Task<OidcError?> Validate(string applicationType, string authMethod, bool? pkceRequired)
        => await _validator.ValidateAsync(
            SingleIssuer.Tenant,
            new ClientRegistrationValidationContext(new ClientRegistrationRequest
            {
                RedirectUris = [TestConstants.DefaultRedirectUri],
                ApplicationType = applicationType,
                TokenEndpointAuthMethod = authMethod,
                PkceRequired = pkceRequired,
            }));
}
