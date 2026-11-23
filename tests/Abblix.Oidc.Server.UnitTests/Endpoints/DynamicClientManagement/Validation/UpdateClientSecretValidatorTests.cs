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
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// RFC 7592 section 2.2: a client_secret an update carries "MUST match the currently issued client secret for that
/// client", so an update carrying another is refused with invalid_client_metadata, while one carrying the issued secret
/// or none at all passes, and a new registration is not judged by it.
/// </summary>
public class UpdateClientSecretValidatorTests
{
    private const string IssuedSecret = "the-secret-issued-to-the-client";

    private static readonly HashService Hashes = new();

    private static ClientInfo StoredClient() => new(TestConstants.DefaultClientId)
    {
        ClientSecrets = [new ClientSecret { Sha512Hash = Hashes.Sha(HashAlgorithm.Sha512, IssuedSecret) }],
    };

    [Theory]
    [InlineData("another-secret", true)]
    [InlineData("", true)]
    [InlineData(IssuedSecret, false)]
    [InlineData(null, false)]
    public async Task AnUpdate_IsRefusedOnlyForASecretThatIsNotTheIssuedOne(string? presented, bool refused)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest { ClientSecret = presented })
        {
            Operation = DynamicClientOperation.Update,
            StoredClient = StoredClient(),
        };

        var error = await new UpdateClientSecretValidator(Hashes).ValidateAsync(SingleIssuer.Tenant, context);

        if (!refused)
        {
            Assert.Null(error);
            return;
        }

        Assert.NotNull(error);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    [Fact]
    public async Task AClientHoldingNoSecret_IsRefusedAnUpdateNamingOne()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest { ClientSecret = IssuedSecret })
        {
            Operation = DynamicClientOperation.Update,
            StoredClient = new ClientInfo(TestConstants.DefaultClientId),
        };

        var error = await new UpdateClientSecretValidator(Hashes).ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, error?.Error);
    }

    [Fact]
    public async Task ARegistration_IsNotJudgedByTheSecretItCarries()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest { ClientSecret = "chosen" });

        Assert.Null(await new UpdateClientSecretValidator(Hashes).ValidateAsync(SingleIssuer.Tenant, context));
    }
}
