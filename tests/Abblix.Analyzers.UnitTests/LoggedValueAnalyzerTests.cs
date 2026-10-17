// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Analyzers.UnitTests;

/// <summary>
/// A value a sender chose reaches the log only sanitized, and a credential only as its fingerprint, by whatever route
/// it takes inside the method; a value the server owns, and one that cannot carry text, are left alone.
/// </summary>
public class LoggedValueAnalyzerTests
{
    /// <summary>
    /// The types the rule asks for, under the names the real ones carry, and a request the way the server's models
    /// are marked.
    /// </summary>
    private const string Declarations = """
        namespace Microsoft.Extensions.Logging
        {
            [System.AttributeUsage(System.AttributeTargets.Method)]
            public sealed class LoggerMessageAttribute : System.Attribute { }
        }

        namespace Abblix.Utils
        {
            public readonly struct Sanitized
            {
                public static implicit operator Sanitized(string? source) => default;
                public static Sanitized[] Values(System.Collections.Generic.IEnumerable<object?> sources) => [];
            }

            public readonly struct Fingerprint { }

            [System.AttributeUsage(System.AttributeTargets.Class | System.AttributeTargets.Struct)]
            public sealed class ExternalInputAttribute : System.Attribute { }

            [System.AttributeUsage(
                System.AttributeTargets.Property | System.AttributeTargets.Field | System.AttributeTargets.Parameter)]
            public sealed class CredentialAttribute : System.Attribute { }
        }

        namespace Sample
        {
            using Abblix.Utils;

            [ExternalInput]
            public class Request
            {
                public string? ClientId { get; set; }
                public string[] Scope { get; set; } = [];
                public int MaxAge { get; set; }
                [Credential] public string? Code { get; set; }
            }

            public sealed class TokenRequest : Request
            {
                public string? GrantType { get; set; }
            }

            public sealed class Client
            {
                public string ClientId { get; set; } = "";
            }

            public static class Fingerprints
            {
                public static Fingerprint Of(string? value) => default;
            }
        }
        """;

    private static Task<IReadOnlyList<string>> IdsOf(string body) => IdsOf(body, Declarations);

    private static async Task<IReadOnlyList<string>> IdsOf(string body, string declarations)
    {
        var source = declarations + $$"""

            namespace Sample
            {
                using Abblix.Utils;
                using Microsoft.Extensions.Logging;

                public partial class Endpoint
                {
                    [LoggerMessage] private static void LogText(string? text) { }
                    [LoggerMessage] private static void LogObject(object? value) { }
                    [LoggerMessage] private static void LogList(string[] values) { }
                    [LoggerMessage] private static void LogSanitized(Sanitized value) { }
                    [LoggerMessage] private static void LogSanitizedList(Sanitized[]? values) { }
                    [LoggerMessage] private static void LogFingerprint(Fingerprint value) { }
                    [LoggerMessage] private static void LogCount(int count) { }
                    private static void Trace(string? text) { }
                    private static Client Find(string? clientId) => new();

                    {{body}}
                }
            }
            """;

        var diagnostics = await AnalyzerRun.DiagnosticsOf(new LoggedValueAnalyzer(), source);
        return [.. diagnostics.Select(diagnostic => diagnostic.Id)];
    }

    [Theory]
    [InlineData("void M(Request request) => LogText(request.ClientId);")]
    [InlineData("void M(Request request) => LogText($\"client {request.ClientId}\");")]
    [InlineData("void M(Request request) => LogText(request.ClientId?.Trim());")]
    [InlineData("void M(Request request) => LogText(string.Join(\",\", request.Scope));")]
    [InlineData("void M(Request request) => LogList(request.Scope);")]
    [InlineData("void M(Request request) => LogObject(request);")]
    [InlineData("void M(TokenRequest request) => LogText(request.ClientId);")]
    [InlineData("void M(TokenRequest request) => LogText(request.GrantType);")]
    [InlineData("void M(Request request) { var clientId = request.ClientId; LogText(clientId); }")]
    [InlineData("void M(Request request) { string? id; id = request.ClientId; LogText(id); }")]
    [InlineData("void M(Request request) { if (request.ClientId is { } id) LogText(id); }")]
    [InlineData("void M(Request request) { if (request is { ClientId: { } id }) LogText(id); }")]
    [InlineData("void M(Request request) { foreach (var scope in request.Scope) LogText(scope); }")]
    public async Task AValueFromOutside_LoggedUnsanitized_IsReported(string body)
        => Assert.Equal([LoggedValueAnalyzer.ExternalInputRule.Id], await IdsOf(body));

    [Theory]
    [InlineData("void M(Request request) => LogSanitized(request.ClientId);")]
    [InlineData("void M(Request request) { var clientId = request.ClientId; LogSanitized(clientId); }")]
    [InlineData("void M(Request request) => LogSanitizedList(Sanitized.Values(request.Scope));")]
    [InlineData("void M(Request request) => LogFingerprint(Fingerprints.Of(request.ClientId));")]
    public async Task AValueFromOutside_LoggedSanitized_IsNotReported(string body)
        => Assert.Empty(await IdsOf(body));

    /// <summary>
    /// What the server looked up or computed, though by a value that was sent, is the server's own, and a count or an
    /// age cannot carry the text a sender chose.
    /// </summary>
    [Theory]
    [InlineData("void M(Request request) { var client = Find(request.ClientId); LogText(client.ClientId); }")]
    [InlineData("void M(Request request) => LogText(Find(request.ClientId).ClientId);")]
    [InlineData("void M(Request request) => LogCount(request.MaxAge);")]
    [InlineData("void M(Request request) => LogCount(request.Scope.Length);")]
    [InlineData("void M(Request request) { var age = request.MaxAge; LogText(age.ToString()); }")]
    [InlineData("void M(Client client) => LogText(client.ClientId);")]
    public async Task AValueTheServerOwns_IsNotReported(string body)
        => Assert.Empty(await IdsOf(body));

    [Theory]
    [InlineData("void M(Request request) => LogText(request.Code);")]
    [InlineData("void M(Request request) => LogSanitized(request.Code);")]
    [InlineData("void M(Request request) { var code = request.Code; LogSanitized(code); }")]
    [InlineData("void M(Request request) { if (request is { Code: { } code }) LogText(code); }")]
    [InlineData("void M([Credential] string code) => LogText(code);")]
    [InlineData("void M([Credential] string code) => LogSanitized($\"code {code}\");")]
    [InlineData("void M([Credential] string code) { var copy = code; LogText(copy); }")]
    public async Task ACredential_LoggedOtherThanAsItsFingerprint_IsReported(string body)
        => Assert.Equal([LoggedValueAnalyzer.CredentialRule.Id], await IdsOf(body));

    [Theory]
    [InlineData("void M(Request request) => LogFingerprint(Fingerprints.Of(request.Code));")]
    [InlineData("void M([Credential] string code) => LogFingerprint(Fingerprints.Of(code));")]
    [InlineData("void M([Credential] string code) => LogCount(code.Length);")]
    public async Task ACredential_LoggedAsItsFingerprint_IsNotReported(string body)
        => Assert.Empty(await IdsOf(body));

    /// <summary>
    /// A method without <c>[LoggerMessage]</c> writes no record, so what it is given is not the rule's business.
    /// </summary>
    [Fact]
    public async Task ACallThatWritesNoRecord_IsNotReported()
        => Assert.Empty(await IdsOf("void M(Request request) => Trace(request.Code);"));

    /// <summary>
    /// The generator declares a logging method as a partial pair; the mark sits on the part somebody wrote.
    /// </summary>
    [Fact]
    public async Task APartialLoggingMethod_IsJudgedByItsDeclaration()
    {
        var ids = await IdsOf("""
            [LoggerMessage] private static partial void LogPartial(string? text);
            private static partial void LogPartial(string? text) { }
            void M(Request request) => LogPartial(request.ClientId);
            """);

        Assert.Equal([LoggedValueAnalyzer.ExternalInputRule.Id], ids);
    }

    /// <summary>
    /// A compilation that cannot see the wrappers has nothing to log through, so it is not held to the rule; the same
    /// sample with them is, which shows the silence here is the missing types' and not a sample the rule cannot read.
    /// </summary>
    [Fact]
    public async Task ACompilationWithoutTheWrappers_IsNotHeldToTheRule()
    {
        const string body = "void M(Request request) => LogText(request.ClientId);";
        var withoutCredential = Declarations
            .Replace("CredentialAttribute", "OtherAttribute", StringComparison.Ordinal)
            .Replace("[Credential]", "[Other]", StringComparison.Ordinal);

        Assert.Empty(await IdsOf(body, withoutCredential));
        Assert.NotEmpty(await IdsOf(body));
    }

    /// <summary>
    /// The rule finds the real types by the names it holds, so a type renamed or moved would switch the rule off with
    /// every build still green.
    /// </summary>
    [Fact]
    public void TheNamesTheRuleLooksFor_AreTheRealTypes()
    {
        Assert.Equal(LoggedValueAnalyzer.LoggerMessageAttributeName, typeof(LoggerMessageAttribute).FullName);
        Assert.Equal(LoggedValueAnalyzer.SanitizedName, typeof(Sanitized).FullName);
        Assert.Equal(LoggedValueAnalyzer.FingerprintName, typeof(Fingerprint).FullName);
        Assert.Equal(LoggedValueAnalyzer.ExternalInputAttributeName, typeof(ExternalInputAttribute).FullName);
        Assert.Equal(LoggedValueAnalyzer.CredentialAttributeName, typeof(CredentialAttribute).FullName);
    }
}
