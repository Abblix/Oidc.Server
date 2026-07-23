// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Collections.Generic;
using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Configuration;

/// <summary>
/// What a host gets when it binds a configuration section that leaves a required setting out.
/// </summary>
public class PartialConfigurationTests
{
    /// <summary>
    /// A verification URI that was never configured names itself when read.
    /// </summary>
    /// <remarks>
    /// The C# <c>required</c> modifier is an obligation on an object initialiser and nothing more. The
    /// configuration binder does not honour it, and for an absent reference-typed member it never calls the
    /// setter at all - so a host that binds a partial section gets an options object the compiler believes
    /// is complete. Before this was asserted here, the missing setting surfaced as an
    /// ArgumentNullException out of a URI builder on every device authorization request, naming the
    /// plumbing rather than the setting.
    /// The instance is created the way the binder creates one, bypassing the initialiser, because that is
    /// the only path on which this can happen. Writing the test with an object initialiser would not
    /// compile without supplying the very value whose absence is under test.
    /// </remarks>
    [Fact]
    public void AVerificationUriLeftOutOfConfigurationNamesItself()
    {
        var options = Activator.CreateInstance<DeviceAuthorizationOptions>();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // A section that is present and plausible, and simply does not mention the URI. A typo in
                // the key name reaches here identically, since unknown keys are dropped without a word.
                // The other settings carry values because their setters validate, which is itself the
                // contrast worth seeing: a bad value is caught where it is written, an absent one is not.
                ["DeviceCodeLength"] = "32",
                ["UserCodeLength"] = "8",
            })
            .Build();

        // The binder reads the property as well as writing it, so the refusal lands while the section is
        // being bound rather than on the first request that needed the URI. That is the better end to fail
        // at, and it is asserted here rather than assumed: a host learns at startup that its section is
        // incomplete, with the setting named, instead of learning it from a request that blows up later.
        // Wrapped by reflection on the way out of the binder, so the assertion reaches through it. What
        // matters is the sentence a host reads, and it names the setting.
        var wrapped = Assert.Throws<TargetInvocationException>(() => configuration.Bind(options));
        var error = Assert.IsType<InvalidOperationException>(wrapped.InnerException);
        Assert.Contains(nameof(DeviceAuthorizationOptions.VerificationUri), error.Message, StringComparison.Ordinal);
    }
}
