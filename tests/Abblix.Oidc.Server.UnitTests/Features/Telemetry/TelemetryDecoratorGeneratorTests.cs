// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.SourceGenerators.Telemetry;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// The build generates the decorator of each handler an assembly lists, and refuses a list it cannot honor.
/// </summary>
public sealed class TelemetryDecoratorGeneratorTests
{
    [Fact]
    public async Task AHandlerAddedToTheList_GetsADecoratorThatRunsItInASpan()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == OidcTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = stopped.Add,
        };
        ActivitySource.AddActivityListener(listener);

        await using var services = new ServiceCollection().AddMetrics().BuildServiceProvider();
        var inner = new Mock<IProbeHandler>();
        inner.Setup(h => h.HandleAsync("request")).ReturnsAsync("handled");
        var decorator = new ObservedProbeHandler(
            inner.Object,
            new OidcInstruments(NullLoggerFactory.Instance, services.GetRequiredService<IMeterFactory>()));

        var trace = ActivityTraceId.CreateRandom();
        using (new Activity("test").SetParentId(trace, ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded).Start())
        {
            Assert.True((await decorator.HandleAsync("request")).TryGetSuccess(out var handled));
            Assert.Equal("handled", handled);
        }

        var span = Assert.Single(stopped, span => span.TraceId == trace);
        Assert.Equal(TelemetryEndpoints.Introspection, span.GetTagItem(TelemetryTags.Endpoint));
    }

    [Theory]
    [InlineData("public class NotAnInterface {}", "typeof(NotAnInterface)", "ABXT001")]
    [InlineData("public interface IVoidHandler { void Handle(); }", "typeof(IVoidHandler)", "ABXT002")]
    public void AListTheGeneratorCannotHonor_FailsTheBuild(string declaration, string service, string id)
    {
        const string attribute = """
            namespace Abblix.Oidc.Server.Features.Telemetry
            {
                [System.AttributeUsage(System.AttributeTargets.Assembly, AllowMultiple = true)]
                internal sealed class ObservedEndpointAttribute(System.Type service, string endpoint) : System.Attribute;
            }
            """;
        var list = $"""
            [assembly: Abblix.Oidc.Server.Features.Telemetry.ObservedEndpoint({service}, "token")]

            {declaration}
            """;
        var compilation = CSharpCompilation.Create(
            "probe",
            [
                CSharpSyntaxTree.ParseText(attribute, cancellationToken: TestContext.Current.CancellationToken),
                CSharpSyntaxTree.ParseText(list, cancellationToken: TestContext.Current.CancellationToken),
            ],
            // The platform's assemblies, so the attribute's base type resolves and the generator recognizes it
            ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
                .Split(Path.PathSeparator)
                .Where(File.Exists)
                .Select(path => MetadataReference.CreateFromFile(path)),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics(TestContext.Current.CancellationToken)
            .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));

        var result = CSharpGeneratorDriver.Create(new TelemetryDecoratorGenerator())
            .RunGenerators(compilation, TestContext.Current.CancellationToken)
            .GetRunResult();

        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(id, diagnostic.Id);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Empty(result.GeneratedTrees);
    }
}
