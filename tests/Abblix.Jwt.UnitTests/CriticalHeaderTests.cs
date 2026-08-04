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

using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for the JWS 'crit' header parameter validation per RFC 7515 §4.1.11. Tokens are
/// signed with a real RSA key so the signature step passes; the focus is on the post-signature
/// 'crit' validation pass that decides whether the JOSE header itself is acceptable. Library
/// ships with zero <see cref="ICriticalHeaderHandler"/> implementations by default - the
/// «no handler registered» tests exercise the rejection branch, the handler-backed tests
/// register a test-double handler for <c>"b64"</c> to walk the happy and side-effect paths.
/// </summary>
public class CriticalHeaderTests
{
    private const string IssuerUri = "https://issuer.example.com";
    private const string TestAudience = "test-audience";
    private const string ExtensionName = "b64";

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// A JWS without 'crit' validates exactly as before; the new pass is a no-op when 'crit'
    /// is absent, which is the overwhelming common case.
    /// </summary>
    [Fact]
    public async Task TokenWithoutCrit_Validates()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: null, extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Per RFC 7515 §4.1.11 a producer MUST NOT use the empty list as 'crit'. The validator
    /// rejects malformed input as recipient-MAY.
    /// </summary>
    [Fact]
    public async Task TokenWithEmptyCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: new JsonArray(), extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST NOT include header parameter names defined by RFC 7515 / JWA. 'alg' is
    /// always present in the JOSE header but is reserved, so listing it in 'crit' is rejected.
    /// </summary>
    [Theory]
    [InlineData(JwtClaimTypes.Algorithm)]
    [InlineData(JwtClaimTypes.KeyId)]
    [InlineData(JwtClaimTypes.Type)]
    [InlineData(JwtClaimTypes.Critical)]
    [InlineData(JwtClaimTypes.X509Sha256Thumbprint)]
    public async Task TokenWithReservedNameInCrit_FailsValidation(string reservedName)
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)reservedName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST NOT contain duplicate names.
    /// </summary>
    [Fact]
    public async Task TokenWithDuplicateNamesInCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName, (JsonNode)ExtensionName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Every name in 'crit' MUST also appear as a header parameter in the JOSE header.
    /// A name in 'crit' but absent from the header is a "dangling" reference - the validator
    /// rejects on this earlier guard before reaching the "unknown extension" fallthrough.
    /// </summary>
    [Fact]
    public async Task TokenWithCritNameNotPresentInHeader_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// A 'crit' name that names an extension this library does not understand MUST be rejected
    /// (RFC 7515 §4.1.11: "If any of the listed extension Header Parameters are not understood
    /// and supported by the recipient, then the JWS is invalid"). The library currently
    /// understands no extensions, so any well-formed 'crit' that survives the malformation
    /// guards lands here.
    /// </summary>
    [Fact]
    public async Task TokenWithUnknownExtensionInCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST be a JSON array; a scalar value is malformed.
    /// </summary>
    [Fact]
    public async Task TokenWithCritNotAnArray_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: 42, extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST contain only string values; a non-string array element is malformed.
    /// </summary>
    [Fact]
    public async Task TokenWithCritContainingNonString_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName, 42),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// When the host registers a handler under the 'crit' name and the matching header is
    /// present, validation succeeds. This is the happy path that lets a future RFC 7797 /
    /// RFC 8225 / custom extension plug in without further library changes.
    /// </summary>
    [Fact]
    public async Task TokenWithRegisteredHandlerInCrit_Validates()
    {
        var sp = CreateServiceProvider(services =>
            services.AddCriticalHeaderHandler<NoopB64Handler>(ExtensionName));
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// When a registered handler rejects the JWS, the validator surfaces the handler's
    /// <see cref="JwtValidationError"/> verbatim - confirming that the handler is actually
    /// invoked (not bypassed by an earlier guard) and that its decision is the validator's
    /// decision.
    /// </summary>
    [Fact]
    public async Task HandlerReturningError_PropagatesAsValidationFailure()
    {
        var sp = CreateServiceProvider(services =>
            services.AddCriticalHeaderHandler<RejectingB64Handler>(ExtensionName));
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Equal(RejectingB64Handler.RejectionReason, error.ErrorDescription);
    }

    /// <summary>
    /// Routing is keyed on the DI registration name, not the handler type. A handler registered
    /// under a different name does not make the 'crit' name in the token routable, so the JWS is
    /// still rejected as «unknown critical header parameter».
    /// </summary>
    [Fact]
    public async Task HandlerRegisteredUnderDifferentName_DoesNotRouteCritName()
    {
        const string otherName = "ppt";
        var sp = CreateServiceProvider(services =>
            services.AddCriticalHeaderHandler<NoopB64Handler>(otherName));
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    private static IServiceProvider CreateServiceProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Test-double handler for <c>"b64"</c> (RFC 7797 name reused here for convenience; this
    /// handler does not implement RFC 7797's signature-input transformation - the JWS we sign
    /// carries a bare boolean header field). Always short-circuits to success, matching the
    /// «signature-affecting extension whose work lives in the signing pipeline» mode. The name
    /// it answers to is the DI key it is registered under, not a property.
    /// </summary>
    private sealed class NoopB64Handler : ICriticalHeaderHandler
    {
        public Task<JwtValidationError?> HandleAsync(CriticalHeaderContext context, CancellationToken cancellationToken)
            => Task.FromResult<JwtValidationError?>(null);
    }

    /// <summary>
    /// Test-double handler that rejects every JWS - used to verify that handler rejection
    /// actually propagates through the validator (and that no earlier guard short-circuits
    /// past the handler invocation).
    /// </summary>
    private sealed class RejectingB64Handler : ICriticalHeaderHandler
    {
        public const string RejectionReason = "test-double handler rejection";

        public Task<JwtValidationError?> HandleAsync(CriticalHeaderContext context, CancellationToken cancellationToken)
            => Task.FromResult<JwtValidationError?>(
                new JwtValidationError(JwtError.InvalidToken, RejectionReason));
    }

    private static async Task<string> IssueTokenWithHeader(
        IServiceProvider sp,
        JsonNode? criticalNode,
        JsonNode? extensionValue)
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = IssuerUri,
                Audiences = [TestAudience],
                ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1),
            },
        };

        if (criticalNode is not null)
            token.Header.Json[JwtClaimTypes.Critical] = criticalNode;
        if (extensionValue is not null)
            token.Header.Json[ExtensionName] = extensionValue;

        var creator = sp.GetRequiredService<IJsonWebTokenCreator>();
        return await creator.IssueAsync(token, SigningKey);
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> Validate(IServiceProvider sp, string jwt)
    {
        var validator = sp.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
            Options = ValidationOptions.Default,
        };
        return await validator.ValidateAsync(jwt, parameters);
    }

}
