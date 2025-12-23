using Xunit;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// xUnit collection definition for tests that require license configuration.
/// Use [Collection("License")] attribute on test classes to ensure license is set up.
/// </summary>
[CollectionDefinition("License")]
public class LicenseCollection : ICollectionFixture<LicenseFixture>;
