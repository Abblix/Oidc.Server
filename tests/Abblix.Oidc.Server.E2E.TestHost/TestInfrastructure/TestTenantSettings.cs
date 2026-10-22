// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;

namespace Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;

/// <summary>
/// The settings of the one tenant the test host serves, kept apart from the tenant definition so a test can
/// change one of them for its own host before the tenant is built, which an immutable definition does not allow.
/// </summary>
public sealed class TestTenantSettings
{
    /// <summary>The id the test host's tenant is registered under.</summary>
    public const string TenantId = "e2e";

    public Uri Issuer { get; set; } = TestConstants.IssuerUri;
    public ClientInfo[] Clients { get; set; } = [];
    public ResourceDefinition[]? Resources { get; set; }
    public Uri? DefaultResourceIndicator { get; set; }
    public bool InferResourceFromScope { get; set; }
    public Uri? LoginUri { get; set; }
    public Uri? ConsentUri { get; set; }
    public Uri? AccountSelectionUri { get; set; }
    public Uri? RegistrationUri { get; set; }
    public IReadOnlyCollection<JsonWebKey> SigningKeys { get; set; } = [];
    public IReadOnlyCollection<JsonWebKey> EncryptionKeys { get; set; } = [];
    public PairwiseSubjectSettings? PairwiseSubject { get; set; }
    public CustodianHeldKeys? CustodianKeys { get; set; }
    public Uri? MtlsBaseUri { get; set; }

    /// <summary>
    /// The tenant these settings describe.
    /// </summary>
    public TenantDefinition ToTenant() => new()
    {
        Id = TenantId,
        Issuer = Issuer,
        Clients = Clients,
        Resources = Resources,
        DefaultResourceIndicator = DefaultResourceIndicator,
        InferResourceFromScope = InferResourceFromScope,
        LoginUri = LoginUri,
        ConsentUri = ConsentUri,
        AccountSelectionUri = AccountSelectionUri,
        RegistrationUri = RegistrationUri,
        SigningKeys = SigningKeys,
        EncryptionKeys = EncryptionKeys,
        PairwiseSubject = PairwiseSubject,
        CustodianKeys = CustodianKeys,
        MtlsBaseUri = MtlsBaseUri,
    };
}
