using Xunit;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// xUnit collection definition for tests that touch the global static licensing state
/// (<c>LicenseChecker</c>, <c>LicenseLogger.Instance</c>) — whether they mutate it (loading
/// licenses, exercising the checker) or read it through the permissive <see cref="LicenseFixture"/>.
/// Use <c>[Collection("License")]</c> on such test classes.
/// </summary>
/// <remarks>
/// <see cref="DisableParallelization"/> is intentionally <c>true</c>: the licensing state is a
/// process-wide static with no reset hook (a deliberate anti-tamper design), so a test mutating it
/// must never overlap any other test reading or writing it. This collection therefore runs in
/// xUnit's non-parallel phase, isolated from the rest of the suite. Without this, a license-loading
/// test racing the parallel suite leaves the static checker in an unexpected state and produces
/// flaky, CI-only failures.
/// </remarks>
[CollectionDefinition("License", DisableParallelization = true)]
public class LicenseCollection : ICollectionFixture<LicenseFixture>;
