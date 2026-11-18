// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A client registering itself asks for no offline access or for offline access with prompt=consent, and receives
/// the latter when it does not say; waiving prompt=consent is the host's statement about a client, so a client
/// asking for it is refused, unless it updates its registration and the host has already allowed it.
/// </summary>
public class OfflineAccessValidatorTests
{
    private const string ClientId = "registered-client";

    /// <summary>
    /// The validator under test, judging each context as an update of a stored client holding
    /// <paramref name="existing"/> when one is named.
    /// </summary>
    private sealed class Subject(OfflineAccessValidator validator, OfflineAccess? existing)
    {
        public Task<OidcError?> ValidateAsync(TenantDefinition tenant, ClientRegistrationValidationContext context)
        {
            if (existing is { } offlineAccess)
                context.StoredClient = new ClientInfo(ClientId) { OfflineAccess = offlineAccess };

            return validator.ValidateAsync(tenant, context);
        }
    }

    private static Subject Validator(OfflineAccess? existing, OfflineAccess? granted = null)
        => new(
            granted is { } host
                ? new OfflineAccessValidator(new NewClientOptions { OfflineAccess = host })
                : new OfflineAccessValidator(Mock.Of<IClientInfoProvider>(MockBehavior.Strict)),
            existing);

    private static ClientRegistrationValidationContext Context(
        OfflineAccess offlineAccess,
        DynamicClientOperation operation = DynamicClientOperation.Register)
        => new(new ClientRegistrationRequest
        {
            ClientId = ClientId,
            RedirectUris = [TestConstants.DefaultRedirectUri],
            OfflineAccess = offlineAccess,
        })
        {
            Operation = operation,
        };

    [Theory]
    [InlineData(OfflineAccess.Disabled, null)]
    [InlineData(OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, ErrorCodes.InvalidClientMetadata)]
    [InlineData((OfflineAccess)7, ErrorCodes.InvalidClientMetadata)]
    public async Task ARegistration_IsRefusedOfflineAccessWithoutConsentPromptOrAnUnnamedValue(
        OfflineAccess offlineAccess, string? error)
    {
        var result = await Validator(existing: null).ValidateAsync(SingleIssuer.Tenant, Context(offlineAccess));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// RFC 7592 section 2.2 has an update carry the metadata as the server returned it, so a client the host allowed
    /// sends allowed back and keeps it, while a client the host did not allow cannot raise itself to it.
    /// </summary>
    [Theory]
    [InlineData(OfflineAccess.Allowed, null)]
    [InlineData(OfflineAccess.ConsentRequired, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Disabled, ErrorCodes.InvalidClientMetadata)]
    public async Task AnUpdate_KeepsAllowedOnlyForAClientAlreadyAllowed(OfflineAccess existing, string? error)
    {
        var result = await Validator(existing).ValidateAsync(SingleIssuer.Tenant, Context(OfflineAccess.Allowed, DynamicClientOperation.Update));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// A registration may ask for the offline access the host grants new clients or for less, never for more.
    /// </summary>
    [Theory]
    [InlineData(OfflineAccess.Allowed, OfflineAccess.Allowed, null)]
    [InlineData(OfflineAccess.Allowed, OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Allowed, OfflineAccess.Disabled, null)]
    [InlineData(OfflineAccess.ConsentRequired, OfflineAccess.Allowed, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Disabled, OfflineAccess.ConsentRequired, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Disabled, OfflineAccess.Allowed, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Disabled, OfflineAccess.Disabled, null)]
    public async Task ARegistration_MayAskForTheHostsGrantOrLess(OfflineAccess granted, OfflineAccess asked, string? error)
    {
        var result = await Validator(existing: null, granted).ValidateAsync(SingleIssuer.Tenant, Context(asked));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// A registration stating no offline access is registered with what the host grants, so nothing is refused.
    /// </summary>
    [Theory]
    [InlineData(OfflineAccess.Disabled)]
    [InlineData(OfflineAccess.ConsentRequired)]
    [InlineData(OfflineAccess.Allowed)]
    public async Task ARegistrationStatingNoOfflineAccess_IsNotRefused(OfflineAccess granted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            ClientId = ClientId,
            RedirectUris = [TestConstants.DefaultRedirectUri],
        });

        var result = await Validator(existing: null, granted).ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Null(result);
    }

    /// <summary>
    /// An update sending back what the host gave the client keeps it after the host grants new clients less.
    /// </summary>
    [Theory]
    [InlineData(OfflineAccess.ConsentRequired, OfflineAccess.ConsentRequired, null)]
    [InlineData(OfflineAccess.Disabled, OfflineAccess.ConsentRequired, ErrorCodes.InvalidClientMetadata)]
    [InlineData(OfflineAccess.Allowed, OfflineAccess.ConsentRequired, null)]
    public async Task AnUpdate_UnderAHostGrantingNothing_KeepsWhatTheClientHas(
        OfflineAccess existing, OfflineAccess asked, string? error)
    {
        var result = await Validator(existing, granted: OfflineAccess.Disabled)
            .ValidateAsync(SingleIssuer.Tenant, Context(asked, DynamicClientOperation.Update));

        Assert.Equal(error, result?.Error);
    }

    /// <summary>
    /// The parameter carries each value under its registration name, and a request that does not state it asks for
    /// offline access with prompt=consent.
    /// </summary>
    [Theory]
    [InlineData("disabled", OfflineAccess.Disabled)]
    [InlineData("consent_required", OfflineAccess.ConsentRequired)]
    [InlineData("allowed", OfflineAccess.Allowed)]
    [InlineData(null, OfflineAccess.ConsentRequired)]
    public void OfflineAccess_IsReadByItsRegistrationName(string? name, OfflineAccess expected)
        => Assert.Equal(expected, Read(name)?.OfflineAccess);

    /// <summary>
    /// A request that does not state the parameter is told apart from one stating consent_required, so the host's
    /// grant reaches the former only.
    /// </summary>
    [Theory]
    [InlineData("consent_required", OfflineAccess.ConsentRequired)]
    [InlineData(null, null)]
    public void OfflineAccess_IsStatedOnlyWhenSent(string? name, OfflineAccess? expected)
        => Assert.Equal(expected, Read(name)?.StatedOfflineAccess);

    [Fact]
    public void OfflineAccess_OfAnUnknownName_IsNotRead()
        => Assert.Throws<JsonException>(() => Read("always"));

    private static ClientRegistrationRequest? Read(string? offlineAccess)
    {
        var json = new JsonObject();
        if (offlineAccess != null)
            json[ClientRegistrationRequest.Parameters.OfflineAccess] = offlineAccess;

        return json.Deserialize<ClientRegistrationRequest>();
    }
}
