// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Immutable;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.SourceGenerators.Telemetry;

/// <summary>
/// Generates the decorator of each endpoint handler an assembly attribute names: a sealed partial class that runs
/// every method of the handler through the endpoint observation, under the endpoint the attribute names. A
/// hand-written part of the class supplies the hooks the attribute asks for.
/// </summary>
[Generator]
public sealed class TelemetryDecoratorGenerator : IIncrementalGenerator
{
	// The generator targets netstandard2.0 and reads the server's types through compilation symbols only, so their
	// names are mirrored here as constants. A rename on the server side shows as a build error in the generated code,
	// which names the type it no longer finds.
	private const string ObservedEndpointAttributeName = "Abblix.Oidc.Server.Features.Telemetry.ObservedEndpointAttribute";
	private const string TelemetryNamespace = "Abblix.Oidc.Server.Features.Telemetry";
	private const string ResultTypeName = "Abblix.Utils.Result`2";
	private const string OidcErrorTypeName = "Abblix.Oidc.Server.Common.OidcError";
	private const string AuthorizationResponseTypeName =
		"Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse";
	private const string TaskOfTypeName = "System.Threading.Tasks.Task`1";

	private const string TagsRequestProperty = "TagsRequest";
	private const string ObservesResultProperty = "ObservesResult";
	private const string DependenciesProperty = "Dependencies";

	private const string DecoratorPrefix = "Observed";
	private const string InterfacePrefix = "I";

	private static readonly SymbolDisplayFormat FullyQualifiedWithNullability =
		SymbolDisplayFormat.FullyQualifiedFormat.AddMiscellaneousOptions(
			SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier);

	private const string DiagnosticCategory = "Abblix.Oidc.Server.SourceGenerators.Telemetry";

	private static readonly DiagnosticDescriptor ServiceIsNotAnInterface = new(
		id: "ABXT001",
		title: "Observed service is not an interface",
		messageFormat: "'{0}' is named as an observed endpoint handler but is not an interface, so no decorator can " +
		               "implement it",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor UnsupportedMember = new(
		id: "ABXT002",
		title: "Observed member cannot be wrapped",
		messageFormat: "'{0}.{1}' does not return a Task of a result, so the decorator of '{0}' cannot run it in a span",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	/// <inheritdoc />
	public void Initialize(IncrementalGeneratorInitializationContext context)
	{
		var results = context.SyntaxProvider
			.ForAttributeWithMetadataName(
				ObservedEndpointAttributeName,
				predicate: static (node, _) => node is CompilationUnitSyntax,
				transform: static (ctx, _) => new EquatableArray<GenerationResult>(
					ctx.Attributes.Select(Generate).ToArray()))
			.SelectMany(static (results, _) => results);

		context.RegisterSourceOutput(results, static (productionContext, result) =>
		{
			foreach (var diagnostic in result.Diagnostics)
			{
				productionContext.ReportDiagnostic(diagnostic.ToDiagnostic());
			}

			if (result.Source != null)
			{
				productionContext.AddSource(result.HintName, SourceText.From(result.Source, Encoding.UTF8));
			}
		});
	}

	private static GenerationResult Generate(AttributeData attribute)
	{
		var location = LocationInfo.From(
			attribute.ApplicationSyntaxReference?.GetSyntax().GetLocation() ?? Location.None);
		var service = attribute.ConstructorArguments[0].Value as INamedTypeSymbol;
		var endpoint = (string?)attribute.ConstructorArguments[1].Value ?? string.Empty;
		var serviceName = service?.ToDisplayString() ?? string.Empty;

		if (service is not { TypeKind: TypeKind.Interface })
		{
			return new GenerationResult(
				$"{DecoratorPrefix}.{serviceName}.g.cs",
				null,
				new EquatableArray<DiagnosticInfo>([new DiagnosticInfo(ServiceIsNotAnInterface, location, serviceName)]));
		}

		var className = DecoratorPrefix + StripInterfacePrefix(service.Name);
		var tagsRequest = NamedFlag(attribute, TagsRequestProperty);
		var observesResult = NamedFlag(attribute, ObservesResultProperty);
		var dependencies = attribute.NamedArguments
			.Where(argument => argument.Key == DependenciesProperty)
			.SelectMany(argument => argument.Value.Values)
			.Select(value => value.Value)
			.OfType<INamedTypeSymbol>()
			.ToArray();

		var members = service.GetMembers()
			.Concat(service.AllInterfaces.SelectMany(parent => parent.GetMembers()))
			.ToArray();

		var methods = members.OfType<IMethodSymbol>().Where(method => method.MethodKind == MethodKind.Ordinary).ToArray();
		var unsupported = methods.Where(method => ResultOf(method) == null).ToArray();
		if (unsupported.Length > 0)
		{
			return new GenerationResult(
				$"{className}.g.cs",
				null,
				new EquatableArray<DiagnosticInfo>(unsupported
					.Select(method => new DiagnosticInfo(UnsupportedMember, location, serviceName, method.Name))
					.ToArray()));
		}

		var source = new StringBuilder()
			.AppendLine("// <auto-generated/>")
			.AppendLine("#nullable enable")
			.AppendLine("// The tenant a span names is read from the multi-tenancy feature where it is in use")
			.AppendLine("#pragma warning disable ABXMT001")
			.AppendLine()
			.AppendLine($"namespace {TelemetryNamespace};")
			.AppendLine()
			.AppendLine("/// <summary>")
			.AppendLine($"/// Handles a request of <see cref=\"{EscapeXml(service.ToDisplayString())}\"/> in a span of its " +
			            "endpoint and measures it.")
			.AppendLine("/// </summary>")
			.AppendLine($"internal sealed partial class {className} : {service.ToDisplayString(FullyQualifiedWithNullability)}")
			.AppendLine("{");

		AppendConstructor(source, service, className, dependencies);
		foreach (var property in members.OfType<IPropertySymbol>())
			AppendProperty(source, property);

		var endpointLiteral = SymbolDisplay.FormatLiteral(endpoint, quote: true);
		foreach (var method in methods)
			AppendMethod(source, method, endpointLiteral, tagsRequest, observesResult);

		source.AppendLine("}");

		return new GenerationResult(
			$"{className}.g.cs",
			source.ToString(),
			new EquatableArray<DiagnosticInfo>([]));
	}

	private static void AppendConstructor(
		StringBuilder source,
		INamedTypeSymbol service,
		string className,
		INamedTypeSymbol[] dependencies)
	{
		var serviceType = service.ToDisplayString(FullyQualifiedWithNullability);
		source.AppendLine($"\tprivate readonly {serviceType} _inner;");
		foreach (var dependency in dependencies)
		{
			source.AppendLine(
				$"\tprivate readonly {dependency.ToDisplayString(FullyQualifiedWithNullability)} _{DependencyName(dependency)};");
		}

		source
			.AppendLine($"\tprivate readonly global::{TelemetryNamespace}.OidcInstruments _instruments;")
			.AppendLine("\tprivate readonly global::Abblix.Oidc.Server.Features.MultiTenancy.ITenantAccessor? _tenants;")
			.AppendLine()
			.AppendLine($"\tpublic {className}(")
			.AppendLine($"\t\t{serviceType} inner,");
		foreach (var dependency in dependencies)
		{
			source.AppendLine(
				$"\t\t{dependency.ToDisplayString(FullyQualifiedWithNullability)} {DependencyName(dependency)},");
		}

		source
			.AppendLine($"\t\tglobal::{TelemetryNamespace}.OidcInstruments instruments,")
			.AppendLine("\t\tglobal::Abblix.Oidc.Server.Features.MultiTenancy.ITenantAccessor? tenants = null)")
			.AppendLine("\t{")
			.AppendLine("\t\t_inner = inner;");
		foreach (var dependency in dependencies)
			source.AppendLine($"\t\t_{DependencyName(dependency)} = {DependencyName(dependency)};");

		source
			.AppendLine("\t\t_instruments = instruments;")
			.AppendLine("\t\t_tenants = tenants;")
			.AppendLine("\t}")
			.AppendLine();
	}

	private static void AppendProperty(StringBuilder source, IPropertySymbol property)
	{
		var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);
		source
			.AppendLine("\t/// <inheritdoc />")
			.AppendLine($"\tpublic {type} {Escape(property.Name)} => _inner.{Escape(property.Name)};")
			.AppendLine();
	}

	private static void AppendMethod(
		StringBuilder source,
		IMethodSymbol method,
		string endpointLiteral,
		bool tagsRequest,
		bool observesResult)
	{
		var result = ResultOf(method)!;
		var resultType = result.ToDisplayString(FullyQualifiedWithNullability);
		var parameters = string.Join(", ", method.Parameters.Select(parameter =>
			$"{parameter.Type.ToDisplayString(FullyQualifiedWithNullability)} {Escape(parameter.Name)}"));
		var arguments = string.Join(", ", method.Parameters.Select(parameter => Escape(parameter.Name)));
		var errorOf = ErrorOf(result);

		var run = new StringBuilder()
			.Append($"global::{TelemetryNamespace}.EndpointObservation.RunAsync(")
			.Append($"{endpointLiteral}, _instruments, _tenants, () => _inner.{Escape(method.Name)}({arguments}), ")
			.Append($"global::{TelemetryNamespace}.EndpointObservation.{errorOf}");
		if (tagsRequest)
			run.Append($", () => RequestTagOf({arguments})");
		run.Append(')');

		source
			.AppendLine("\t/// <inheritdoc />")
			.AppendLine(observesResult
				? $"\tpublic async global::System.Threading.Tasks.Task<{resultType}> {Escape(method.Name)}({parameters})"
				: $"\tpublic global::System.Threading.Tasks.Task<{resultType}> {Escape(method.Name)}({parameters})");

		if (observesResult)
		{
			source
				.AppendLine("\t{")
				.AppendLine($"\t\tvar result = await {run};")
				.AppendLine("\t\tObserve(result);")
				.AppendLine("\t\treturn result;")
				.AppendLine("\t}")
				.AppendLine()
				.AppendLine("\t/// <summary>")
				.AppendLine("\t/// Looks at what the handler returned, once it has returned it.")
				.AppendLine("\t/// </summary>")
				.AppendLine($"\tprivate partial void Observe({resultType} result);");
		}
		else
		{
			source.AppendLine($"\t\t=> {run};");
		}

		if (tagsRequest)
		{
			source
				.AppendLine()
				.AppendLine("\t/// <summary>")
				.AppendLine("\t/// The attribute of the request the span names, from the closed set its key documents.")
				.AppendLine("\t/// </summary>")
				.AppendLine($"\tprivate partial (string Key, string? Value) RequestTagOf({parameters});");
		}

		source.AppendLine();
	}

	/// <summary>
	/// The type a method's task carries, or null when it returns anything other than a task of a result.
	/// </summary>
	private static ITypeSymbol? ResultOf(IMethodSymbol method)
		=> method.ReturnType is INamedTypeSymbol { IsGenericType: true } returned &&
		   MetadataName(returned.OriginalDefinition) == TaskOfTypeName
			? returned.TypeArguments[0]
			: null;

	/// <summary>
	/// The member of the endpoint observation that tells the error a result refuses its request with.
	/// </summary>
	private static string ErrorOf(ITypeSymbol result)
	{
		if (result is INamedTypeSymbol { IsGenericType: true } named &&
		    MetadataName(named.OriginalDefinition) == ResultTypeName &&
		    MetadataName(named.TypeArguments[1]) == OidcErrorTypeName)
		{
			return "ErrorOf";
		}

		for (var type = result; type != null; type = type.BaseType)
		{
			if (MetadataName(type) == AuthorizationResponseTypeName)
				return "ErrorOf";
		}

		return "NoError";
	}

	private static string MetadataName(ITypeSymbol type)
		=> type.ContainingNamespace is { IsGlobalNamespace: false } ns
			? $"{ns.ToDisplayString()}.{type.MetadataName}"
			: type.MetadataName;

	private static bool NamedFlag(AttributeData attribute, string name)
		=> attribute.NamedArguments.Any(argument => argument.Key == name && argument.Value.Value is true);

	private static string StripInterfacePrefix(string name)
		=> name.StartsWith(InterfacePrefix, StringComparison.Ordinal) ? name.Substring(InterfacePrefix.Length) : name;

	private static string DependencyName(INamedTypeSymbol dependency)
	{
		var name = StripInterfacePrefix(dependency.Name);
		return char.ToLowerInvariant(name[0]) + name.Substring(1);
	}

	private static string Escape(string identifier)
		=> SyntaxFacts.GetKeywordKind(identifier) != SyntaxKind.None ? "@" + identifier : identifier;

	private static string EscapeXml(string text)
		=> text.Replace("<", "{").Replace(">", "}");
}
