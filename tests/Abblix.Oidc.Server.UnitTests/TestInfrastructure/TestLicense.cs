// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections;
using System.Reflection;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using Abblix.Oidc.Server.Features.Licensing;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Installs the generated test licence for the whole assembly, and names the terms every test lives inside.
/// </summary>
/// <remarks>
/// The suite runs under a real licence loaded the way a deployment loads one, not under lifted limits. A test
/// that removes a limit proves the product works without that limit, which is not the product that ships, and
/// it leaves the limit's own code unreachable so defects can live there indefinitely.
///
/// A module initializer rather than a collection fixture: <see cref="LicenseChecker"/> keeps its state in
/// process-wide statics, so anything that touches it affects every test in the assembly regardless of which
/// collection declared it. Loading once, before the first test runs, is the only arrangement that matches how
/// the state actually behaves.
/// </remarks>
internal static class TestLicense
{
    /// <summary>
    /// The only issuer the test licence recognises. A test that needs an issuer uses this one; any other value
    /// is refused by the licence, which is the correct behaviour and not something to work around.
    /// </summary>
    public const string Issuer = "https://auth.example.com";

    /// <summary>
    /// How many distinct issuers the licence allows. Named here because a test that exercises the limit needs
    /// to know where it sits, and reading it from the JWT at runtime would hide the number from the reader.
    /// </summary>
    public const int IssuerLimit = 1;

    private const string ResourceName = "Abblix.Oidc.Server.UnitTests.Resources.test-license.jwt";

    /// <summary>
    /// Brings <see cref="LicenseChecker"/> back to the state it holds at process start, then reinstalls the
    /// test licence.
    /// </summary>
    /// <remarks>
    /// Everything the checker knows lives in process-wide statics that accumulate and are never released. That
    /// is right for a server, which starts once and runs, and impossible to test against: one test that records
    /// an issuer changes the answer every later test receives, so a limit can never be approached deliberately
    /// by any test that is not the first to run.
    ///
    /// The reach-in lives here rather than behind a hook in the product, because a reset exists only for tests
    /// and test-only code does not belong in a shipped assembly. Note what this does and does not do: it
    /// restores a known starting point and puts the real licence back. It never removes a limit.
    /// </remarks>
    internal static void ResetChecker()
    {
        ClearChecker();
        Install();
    }

    /// <summary>
    /// Empties the checker without installing any licence, so a test can supply terms of its own.
    /// </summary>
    /// <remarks>
    /// Needed because licences accumulate rather than replace one another: adding a licence while the
    /// assembly's is still in place merges the two, and a whitelist from either of them then applies. A test
    /// that wants to reach the issuer-count limit has to arrive with no whitelist at all, since the whitelist
    /// is consulted first and refuses an unknown issuer before any counting happens.
    /// </remarks>
    internal static void ClearChecker()
    {
        var checker = typeof(LicenseChecker);
        const BindingFlags Statics = BindingFlags.NonPublic | BindingFlags.Static;

        checker.GetField("_knownClientIds", Statics)!.SetValue(null, null);
        checker.GetField("_knownIssuers", Statics)!.SetValue(null, null);

        // The manager itself is readonly, so its contents are emptied rather than the instance replaced.
        var manager = checker.GetField("LicenseManager", Statics)!.GetValue(null)!;
        var managerType = manager.GetType();
        const BindingFlags Instances = BindingFlags.NonPublic | BindingFlags.Instance;

        if (managerType.GetField("_licenses", Instances)!.GetValue(manager) is IList licenses)
            licenses.Clear();

        managerType.GetField("_currentLicense", Instances)!.SetValue(manager, null);
    }

    /// <summary>
    /// Empties the throttle window <see cref="LicenseLogger"/> keeps, so a test can observe a record that the
    /// logger would otherwise suppress.
    /// </summary>
    /// <remarks>
    /// The logger is a process-wide singleton and its window is fifteen minutes per key, so whichever test
    /// reaches a limit first consumes the only record anybody can see, and every later test finds the decision
    /// taken in silence. That silence looks exactly like a decision that was never reported at all, which is
    /// why the record went untested while the refusal beside it did not.
    ///
    /// Like <see cref="ClearChecker"/> this reaches into the product rather than asking it for a reset: a
    /// method existing only so a test can call it does not belong in a shipped assembly. It removes nothing
    /// and relaxes nothing - the throttle behaves exactly as it does in a deployment, from an empty start.
    /// </remarks>
    internal static void ClearLogThrottle()
    {
        const BindingFlags Instances = BindingFlags.NonPublic | BindingFlags.Instance;

        var logger = LicenseLogger.Instance;
        var times = logger.GetType().GetField("_nextAllowedTimes", Instances)!.GetValue(logger);

        // A ConcurrentDictionary of an internal key type, so it is emptied through the non-generic interface.
        ((IDictionary)times!).Clear();
    }

    [ModuleInitializer]
    internal static void Install()
    {
        var assembly = typeof(TestLicense).Assembly;

        using var stream = assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException(
                $"The test licence is missing from the assembly as '{ResourceName}'. "
                + $"Embedded resources present: {string.Join(", ", assembly.GetManifestResourceNames())}");

        using var reader = new StreamReader(stream, Encoding.UTF8);

        // Blocking on purpose: a module initializer cannot await, and nothing may observe LicenseChecker before
        // the licence is in place - a check that runs first would be answered by the free licence instead.
        LicenseLoader.LoadAsync(reader.ReadToEnd()).GetAwaiter().GetResult();
    }
}
