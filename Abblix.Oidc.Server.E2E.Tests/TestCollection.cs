// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests;

/// <summary>
/// Sequential test collection for E2E scenarios. The shared
/// <see cref="TestFactory"/> drives a single in-memory host across all
/// tests in this collection so the static <c>LicenseChecker</c> issuer /
/// client dictionaries stay small (one issuer, the pre-seeded clients,
/// plus any DCR-registered ones). <see cref="LicenseFixture"/> removes
/// the FreeLicense numeric ceiling once per run before any test creates
/// a ServiceProvider.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class TestCollection
    : ICollectionFixture<TestFactory>
    , ICollectionFixture<LicenseFixture>
{
    public const string Name = "E2E";
}
