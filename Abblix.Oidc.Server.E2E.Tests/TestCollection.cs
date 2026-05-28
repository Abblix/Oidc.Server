// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Sequential test collection for E2E scenarios. The shared
/// <see cref="TestFactory"/> drives a single in-memory host across all
/// tests in this collection so the static <c>LicenseChecker</c> issuer /
/// client dictionaries stay small (one issuer, the pre-seeded clients,
/// plus any DCR-registered ones). The TestHost itself loads an embedded
/// permissive test license at startup; that license is scoped to
/// <see cref="TestInfrastructure.TestConstants.Issuer"/> via
/// <c>valid_issuers</c>, so it cannot be lifted into a production host.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class TestCollection : ICollectionFixture<TestFactory>
{
    public const string Name = "E2E";
}
