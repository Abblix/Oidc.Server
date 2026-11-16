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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

public class CredentialsValidatorTests
{
    private readonly CredentialsValidator _validator = new();

    /// <summary>What a client_secret_basic or client_secret_post registration stores: the hash alone.</summary>
    private static readonly ClientSecret HashOnly = new() { Sha512Hash = new byte[64] };

    /// <summary>What a client_secret_jwt registration stores: the value, and the hash beside it.</summary>
    private static readonly ClientSecret ValueAndHash = new() { Value = "secret", Sha512Hash = new byte[64] };

    public enum StoredSecret
    {
        None,
        HashOnly,
        ValueAndHash,
    }

    private static ClientRegistrationValidationContext UpdateTo(string method, StoredSecret stored)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            TokenEndpointAuthMethod = method,
        })
        {
            Operation = DynamicClientOperation.Update,
            StoredClient = new ClientInfo("client")
            {
                ClientSecrets = stored switch
                {
                    StoredSecret.None => null,
                    StoredSecret.HashOnly => [HashOnly],
                    StoredSecret.ValueAndHash => [ValueAndHash],
                    _ => throw new System.ArgumentOutOfRangeException(nameof(stored), stored, null),
                },
            },
        };

    /// <summary>
    /// RFC 7592 section 2.2 replaces the metadata but not the secret ("The client MUST NOT be allowed to overwrite its
    /// existing client secret with its own chosen value", and this server issues none on update), so the client keeps
    /// the secrets it holds. An update moving it to a method those secrets cannot serve would leave it unable to
    /// authenticate: client_secret_jwt signs with the secret's value, which a hash cannot give back, and
    /// client_secret_basic and client_secret_post compare against a stored hash, which a client issued no secret does
    /// not have. Such a value is invalid, and "If the client attempts to set an invalid metadata field and the
    /// authorization server does not set a default value, the authorization server responds with an error as described
    /// in [RFC7591]": invalid_client_metadata.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, StoredSecret.HashOnly)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, StoredSecret.None)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, StoredSecret.None)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, StoredSecret.None)]
    public async Task UpdateToAMethodTheStoredSecretsCannotServe_IsRefused(string method, StoredSecret stored)
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, UpdateTo(method, stored));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// The control of the rows above: a secret registered for client_secret_jwt keeps its hash beside its value, so it
    /// serves client_secret_basic and client_secret_post as well; a hash serves those two; and a method that reads no
    /// secret needs none.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, StoredSecret.ValueAndHash)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, StoredSecret.ValueAndHash)]
    [InlineData(ClientAuthenticationMethods.ClientSecretJwt, StoredSecret.ValueAndHash)]
    [InlineData(ClientAuthenticationMethods.ClientSecretBasic, StoredSecret.HashOnly)]
    [InlineData(ClientAuthenticationMethods.ClientSecretPost, StoredSecret.HashOnly)]
    [InlineData(ClientAuthenticationMethods.None, StoredSecret.HashOnly)]
    [InlineData(ClientAuthenticationMethods.None, StoredSecret.None)]
    public async Task UpdateToAMethodTheStoredSecretsServe_IsAccepted(string method, StoredSecret stored)
    {
        Assert.Null(await _validator.ValidateAsync(SingleIssuer.Tenant, UpdateTo(method, stored)));
    }

    /// <summary>
    /// A new registration is issued the secret its method needs, so it is not judged by stored secrets.
    /// </summary>
    [Fact]
    public async Task RegistrationForASecretMethod_IsAccepted()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretJwt,
        });

        Assert.Null(await _validator.ValidateAsync(SingleIssuer.Tenant, context));
    }
}
