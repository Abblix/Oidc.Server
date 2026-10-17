// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A signed token's key identifier is the sender's text and is read before the signature is checked, so it reaches
/// the record and the refusal only through <see cref="Sanitized"/>.
/// </summary>
public class SignatureValidationLoggingTests
{
    [Fact]
    public async Task KeyIdNoKeyMatches_ReachesTheRecordAndTheRefusalWithoutItsLineBreaks()
    {
        var logger = new RecordingLogger<JsonWebTokenSigner>();
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton<ILogger<JsonWebTokenSigner>>(logger);
        var signer = services.BuildServiceProvider().GetRequiredService<IJsonWebTokenSigner>();
        var header = new JsonWebTokenHeader(new JsonObject
        {
            ["alg"] = SigningAlgorithms.RS256,
            ["kid"] = "sent\r\nforged record",
        });
        var issuerKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

        var error = await signer.ValidateAsync(
            ["header", "payload", "signature"],
            header,
            issuerKey.ToAsync(),
            TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.DoesNotContain(error.ErrorDescription, char.IsControl);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogEvents.Jwt.NoMatchingKey, entry.EventId);
        var recorded = Assert.IsType<Sanitized>(entry.Value("KeyId")).ToString();
        Assert.DoesNotContain(recorded, char.IsControl);
        Assert.StartsWith("sent", recorded);
    }
}
