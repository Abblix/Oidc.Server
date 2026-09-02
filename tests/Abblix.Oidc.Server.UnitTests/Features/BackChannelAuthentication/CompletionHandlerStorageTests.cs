// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Reflection;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <summary>
/// The one door out of a completion handler, held by reading the TYPES rather than the call sites.
/// </summary>
/// <remarks>
/// A completion handler that keeps its own <see cref="IBackChannelRequestStorage"/> can write a status
/// without waking anybody, and that is not a hypothetical: ping shipped that way and signalled nothing
/// while its clients waited, and push did the same afterwards. Both were caught by a reviewer.
/// <para>
/// The compiler does NOT hold this. A field initialised from a primary-constructor parameter captures
/// nothing, so <c>private readonly IBackChannelRequestStorage _storage = storage;</c> compiles cleanly
/// beside a base call passing the same parameter - which is exactly the line both defects were made of.
/// Only the direct use of the parameter in a derived body is refused, by CS9107, and that is a different
/// shape from the one that keeps happening.
/// </para>
/// <para>
/// A row per known handler would be complete only until the next handler is added, which is the failure
/// this test is about. So it enumerates the assembly instead: any type deriving from
/// <see cref="AuthenticationCompletionHandler"/>, including one written after this line.
/// </para>
/// </remarks>
public class CompletionHandlerStorageTests
{
    [Fact]
    public void NoCompletionHandlerKeepsItsOwnStorage()
    {
        var handlers = typeof(AuthenticationCompletionHandler).Assembly
            .GetTypes()
            .Where(type => type.IsSubclassOf(typeof(AuthenticationCompletionHandler)))
            .ToArray();

        // The control: an empty set would pass every assertion below, and this test would then be
        // reporting on nothing at all - which reads exactly like a codebase that holds the property.
        Assert.NotEmpty(handlers);

        var offenders = handlers
            .SelectMany(type => type
                .GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.DeclaredOnly)
                .Where(field => field.FieldType == typeof(IBackChannelRequestStorage))
                .Select(field => $"{type.Name}.{field.Name}"))
            .ToArray();

        Assert.Empty(offenders);
    }
}
