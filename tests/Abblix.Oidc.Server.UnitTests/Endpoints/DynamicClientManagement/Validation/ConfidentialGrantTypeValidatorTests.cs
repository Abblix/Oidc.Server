// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// RFC 6749 section 4.4: the client credentials grant "MUST only be used by confidential clients", and this server
/// holds the password and JWT bearer grants to the same rule, so a registration or an update giving one of them to a
/// client authenticating with none is refused with invalid_client_metadata, while a client that authenticates keeps
/// them and a public client keeps the grants an end user takes part in.
/// </summary>
public class ConfidentialGrantTypeValidatorTests
{
    [Theory]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.ClientCredentials, true)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.Password, true)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.JwtBearer, true)]
    [InlineData(ClientAuthenticationMethods.None, GrantTypes.RefreshToken, false)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, GrantTypes.ClientCredentials, false)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, GrantTypes.Password, false)]
    public async Task AGrantKeptForConfidentialClients_IsRefusedToAPublicOneAlone(
        string authenticationMethod, string grantType, bool refused)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            TokenEndpointAuthMethod = authenticationMethod,
            GrantTypes = [grantType],
            ResponseTypes = [],
        });

        var error = await new ConfidentialGrantTypeValidator().ValidateAsync(SingleIssuer.Tenant, context);

        if (!refused)
        {
            Assert.Null(error);
            return;
        }

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }
}
