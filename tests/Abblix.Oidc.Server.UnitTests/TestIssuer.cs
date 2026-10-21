// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests;

/// <summary>
/// The settings of the one tenant a test's services are built for, written as an object initializer and changed
/// afterwards as a reload would change them, which the immutable tenant definition does not allow.
/// </summary>
internal sealed class TestIssuer
{
    /// <summary>The id the tenant is registered under.</summary>
    public const string TenantId = "main";

    public Uri Issuer { get; set; } = TestConstants.DefaultIssuer;
    public IEnumerable<ClientInfo> Clients { get; set; } = [];
    public ScopeDefinition[]? Scopes { get; set; }
    public ResourceDefinition[]? Resources { get; set; }
    public Uri? DefaultResourceIndicator { get; set; }
    public bool InferResourceFromScope { get; set; }
    public Uri? AccountSelectionUri { get; set; }
    public Uri? ConsentUri { get; set; }
    public Uri? InteractionUri { get; set; }
    public Uri? LoginUri { get; set; }
    public Uri? RegistrationUri { get; set; }
    public ClientSecurityProfile DefaultSecurityProfile { get; set; } = ClientSecurityProfile.None;
    public PairwiseSubjectSettings? PairwiseSubject { get; set; }
    public IReadOnlyCollection<JsonWebKey> SigningKeys { get; set; } = [];
    public IReadOnlyCollection<JsonWebKey> EncryptionKeys { get; set; } = [];
    public CustodianHeldKeys? CustodianKeys { get; set; }
    public Uri? MtlsBaseUri { get; set; }
    public MtlsAliasesOptions? MtlsEndpointAliases { get; set; }

    /// <summary>
    /// The tenant these settings describe.
    /// </summary>
    public TenantDefinition ToTenant() => new()
    {
        Id = TenantId,
        Issuer = Issuer,
        Clients = Clients,
        Scopes = Scopes,
        Resources = Resources,
        DefaultResourceIndicator = DefaultResourceIndicator,
        InferResourceFromScope = InferResourceFromScope,
        AccountSelectionUri = AccountSelectionUri,
        ConsentUri = ConsentUri,
        InteractionUri = InteractionUri,
        LoginUri = LoginUri,
        RegistrationUri = RegistrationUri,
        DefaultSecurityProfile = DefaultSecurityProfile,
        PairwiseSubject = PairwiseSubject,
        SigningKeys = SigningKeys,
        EncryptionKeys = EncryptionKeys,
        CustodianKeys = CustodianKeys,
        MtlsBaseUri = MtlsBaseUri,
        MtlsEndpointAliases = MtlsEndpointAliases,
    };
}
