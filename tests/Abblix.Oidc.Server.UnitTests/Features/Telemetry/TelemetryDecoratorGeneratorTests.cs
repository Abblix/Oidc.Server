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

    private const string Ok = "Abblix.Utils.Result<string, Abblix.Oidc.Server.Common.OidcError>";

    [Theory]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(NotAnInterface), \"token\")]",
        "public class NotAnInterface {}",
        "ABXT001", 0, 0)]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(IVoidHandler), \"token\")]",
        "public interface IVoidHandler { void Handle(); }",
        "ABXT002", 0, 0)]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(IOtherErrorHandler), \"token\")]",
        "public interface IOtherErrorHandler { Task<Abblix.Utils.Result<string, string>> HandleAsync(); }",
        "ABXT003", 0, 0)]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(IOkHandler), \"token\")]\n[assembly: ObservedEndpoint(typeof(IOkHandler), \"token\")]",
        "public interface IOkHandler { Task<" + Ok + "> HandleAsync(); }",
        "ABXT005", 1, 1)]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(ITwoMethodHandler), \"token\", TagsRequest = true)]",
        "public interface ITwoMethodHandler { Task<" + Ok + "> FirstAsync(); Task<" + Ok + "> SecondAsync(); }",
        "ABXT006", 0, 0)]
    [InlineData(
        "[assembly: ObservedEndpoint(typeof(IOkHandler), \"token\", Dependencies = new[] { typeof(IInstruments) })]",
        "public interface IOkHandler { Task<" + Ok + "> HandleAsync(); } public interface IInstruments {}",
        "ABXT007", 0, 0)]
    public void AListTheGeneratorCannotHonor_FailsTheBuildAtItsEntry(
        string list,
        string declarations,
        string id,
        int line,
        int generated)
    {
        var (listTree, result) = Run(list, declarations, AbblixReferences);

        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(id, diagnostic.Id);
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Equal(listTree.FilePath, diagnostic.Location.GetLineSpan().Path);
        Assert.Equal(line, diagnostic.Location.GetLineSpan().StartLinePosition.Line);
        Assert.Equal(generated, result.GeneratedTrees.Length);
    }

    [Fact]
    public void ACompilationWithoutTheTypesARefusalIsReadBy_FailsTheBuild()
    {
        var (_, result) = Run(
            "[assembly: ObservedEndpoint(typeof(IPlainHandler), \"token\")]",
            "public interface IPlainHandler { Task<string> HandleAsync(); }",
            []);

        Assert.All(result.Diagnostics, diagnostic => Assert.Equal("ABXT004", diagnostic.Id));
        Assert.NotEmpty(result.Diagnostics);
        Assert.Empty(result.GeneratedTrees);
    }

    private static bool IsManagedAssembly(string path)
    {
        try
        {
            System.Reflection.AssemblyName.GetAssemblyName(path);
            return true;
        }
        catch (BadImageFormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// The assemblies holding the types a refusal is read by.
    /// </summary>
    private static readonly MetadataReference[] AbblixReferences =
    [
        MetadataReference.CreateFromFile(typeof(Abblix.Utils.Result<,>).Assembly.Location),
        MetadataReference.CreateFromFile(typeof(OidcError).Assembly.Location),
    ];

    /// <summary>
    /// Runs the generator over a list of entries and the declarations it names, the list written first in its own file
    /// as assembly attributes have to be.
    /// </summary>
    private static (SyntaxTree List, GeneratorDriverRunResult Result) Run(
        string list,
        string declarations,
        MetadataReference[] references)
    {
        const string attribute = """
            namespace Abblix.Oidc.Server.Features.Telemetry
            {
                [System.AttributeUsage(System.AttributeTargets.Assembly, AllowMultiple = true)]
                internal sealed class ObservedEndpointAttribute(System.Type service, string endpoint) : System.Attribute
                {
                    public bool TagsRequest { get; set; }
                    public bool ObservesResult { get; set; }
                    public System.Type[] Dependencies { get; set; } = [];
                }
            }
            """;
        // Named, since a diagnostic is placed in a file by its path
        var listTree = CSharpSyntaxTree.ParseText(
            list + "\n", path: "List.cs", cancellationToken: TestContext.Current.CancellationToken);
        var declarationsTree = CSharpSyntaxTree.ParseText(
            "using System.Threading.Tasks;\n" + declarations, cancellationToken: TestContext.Current.CancellationToken);
        var compilation = CSharpCompilation.Create(
            "probe",
            [
                CSharpSyntaxTree.ParseText(
                    "global using Abblix.Oidc.Server.Features.Telemetry;\n" + attribute,
                    cancellationToken: TestContext.Current.CancellationToken),
                listTree,
                declarationsTree,
            ],
            // The runtime's own assemblies, so the attribute's base type resolves; the application's assemblies, which
            // the trusted list carries too, come only through the references a case asks for
            Directory.GetFiles(Path.GetDirectoryName(typeof(object).Assembly.Location)!, "*.dll")
                .Where(IsManagedAssembly)
                .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path))
                .Concat(references),
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        Assert.Empty(compilation.GetDiagnostics(TestContext.Current.CancellationToken)
            .Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error));

        var result = CSharpGeneratorDriver.Create(new TelemetryDecoratorGenerator())
            .RunGenerators(compilation, TestContext.Current.CancellationToken)
            .GetRunResult();
        return (listTree, result);
    }
}
