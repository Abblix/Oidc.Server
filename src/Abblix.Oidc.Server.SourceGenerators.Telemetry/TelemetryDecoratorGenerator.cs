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
/// Generates the decorator of each service an assembly attribute names: a sealed partial class that runs every method
/// of an endpoint handler through the endpoint observation, under the endpoint the attribute names, and every method
/// of a stage's service through the stage observation, under the stage. A hand-written part of an endpoint's
/// decorator supplies the hooks its attribute asks for.
/// </summary>
[Generator]
public sealed class TelemetryDecoratorGenerator : IIncrementalGenerator
{
	// The generator targets netstandard2.0 and reads the server's types through compilation symbols only, so their
	// names are mirrored here as constants. A rename of a type the generated code names shows as a build error in that
	// code; a rename of a type a refusal is read by shows as ABXT004, since nothing would name it otherwise.
	private const string ObservedEndpointAttributeName = "Abblix.Oidc.Server.Features.Telemetry.ObservedEndpointAttribute";
	private const string ObservedStageAttributeName = "Abblix.Oidc.Server.Features.Telemetry.ObservedStageAttribute";
	private const string TelemetryNamespace = "Abblix.Oidc.Server.Features.Telemetry";
	private const string ResultTypeName = "Abblix.Utils.Result`2";
	private const string OidcErrorTypeName = "Abblix.Oidc.Server.Common.OidcError";
	private const string AuthorizationResponseTypeName =
		"Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse";
	private const string TaskOfTypeName = "System.Threading.Tasks.Task`1";
	private const string NullableTypeName = "System.Nullable`1";

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

	private static readonly DiagnosticDescriptor UnknownRefusal = new(
		id: "ABXT003",
		title: "Observed result refuses in a way the observation cannot read",
		messageFormat: "'{0}.{1}' returns '{2}', a result whose refusal the endpoint observation has no way to read, " +
		               "so every refusal of it would be measured as a success",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor AnchorNotFound = new(
		id: "ABXT004",
		title: "Type the generator reads results by is not found",
		messageFormat: "The type '{0}' the generator tells a refusal by is not in the compilation; it was renamed or " +
		               "moved, and every result of it would be measured as a success",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor DuplicateDecorator = new(
		id: "ABXT005",
		title: "Two entries name the same decorator",
		messageFormat: "The entry for '{0}' names the decorator '{1}', which an earlier entry of the list already " +
		               "generates under a name differing at most in case",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor HooksNeedOneMethod = new(
		id: "ABXT006",
		title: "Hooks need a handler of one method",
		messageFormat: "'{0}' asks for hooks but has {1} methods, those it inherits included; a hook is declared " +
		               "once and serves one method",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor DependencyNameTaken = new(
		id: "ABXT007",
		title: "Dependency name is taken",
		messageFormat: "The dependency '{0}' of '{1}' would be named '{2}', a name that is empty or one the " +
		               "decorator already uses",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	/// <summary>
	/// The names every decorator takes for itself, which a dependency therefore cannot take.
	/// </summary>
	private static readonly string[] ReservedNames = ["inner", "instruments", "tenants"];

	/// <inheritdoc />
	public void Initialize(IncrementalGeneratorInitializationContext context)
	{
		// Collected across every file of both lists, since a decorator named twice is a fact about the lists together
		var endpoints = Entries(context, ObservedEndpointAttributeName, ObservationKind.Endpoint);
		var stages = Entries(context, ObservedStageAttributeName, ObservationKind.Stage);

		context.RegisterSourceOutput(endpoints.Combine(stages), static (productionContext, lists) =>
		{
			// The compiler holds generated file names unique ignoring case, so two names differing only in case are one
			var generated = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var decorator in lists.Left.Concat(lists.Right))
			{
				foreach (var diagnostic in decorator.Result.Diagnostics)
				{
					productionContext.ReportDiagnostic(diagnostic.ToDiagnostic());
				}

				if (decorator.Result.Source == null)
					continue;

				if (!generated.Add(decorator.ClassName))
				{
					productionContext.ReportDiagnostic(new DiagnosticInfo(
						DuplicateDecorator, decorator.Location, decorator.Service, decorator.ClassName).ToDiagnostic());
					continue;
				}

				productionContext.AddSource(
					decorator.Result.HintName, SourceText.From(decorator.Result.Source, Encoding.UTF8));
			}
		});
	}

	private static IncrementalValueProvider<ImmutableArray<DecoratorResult>> Entries(
		IncrementalGeneratorInitializationContext context,
		string attributeName,
		ObservationKind kind)
		=> context.SyntaxProvider
			.ForAttributeWithMetadataName(
				attributeName,
				predicate: static (node, _) => node is CompilationUnitSyntax,
				transform: (ctx, _) => new EquatableArray<DecoratorResult>(
					ctx.Attributes.Select(attribute => Generate(attribute, ctx.SemanticModel.Compilation, kind)).ToArray()))
			.SelectMany(static (results, _) => results)
			.Collect();

	private static DecoratorResult Generate(AttributeData attribute, Compilation compilation, ObservationKind kind)
	{
		var location = LocationInfo.From(
			attribute.ApplicationSyntaxReference?.GetSyntax().GetLocation() ?? Location.None);
		var service = attribute.ConstructorArguments[0].Value as INamedTypeSymbol;
		var serviceName = service?.ToDisplayString() ?? string.Empty;
		if (service is not { TypeKind: TypeKind.Interface })
		{
			return Refused(
				serviceName, serviceName, location, new DiagnosticInfo(ServiceIsNotAnInterface, location, serviceName));
		}

		var members = service.GetMembers()
			.Concat(service.AllInterfaces.SelectMany(parent => parent.GetMembers()))
			.ToArray();
		var entry = new ObservedEntry(
			service,
			DecoratorPrefix + StripInterfacePrefix(service.Name),
			kind,
			(string?)attribute.ConstructorArguments[1].Value ?? string.Empty,
			NamedFlag(attribute, TagsRequestProperty),
			NamedFlag(attribute, ObservesResultProperty),
			attribute.NamedArguments
				.Where(argument => argument.Key == DependenciesProperty)
				.SelectMany(argument => argument.Value.Values)
				.Select(value => value.Value)
				.OfType<INamedTypeSymbol>()
				.ToArray(),
			members,
			members.OfType<IMethodSymbol>().Where(method => method.MethodKind == MethodKind.Ordinary).ToArray(),
			location);

		var refusals = RefusalsOf(entry, compilation);
		if (refusals.Length > 0)
			return Refused(serviceName, entry.ClassName, location, refusals);

		var generated = new GenerationResult(
			$"{entry.ClassName}.g.cs", Render(entry), new EquatableArray<DiagnosticInfo>([]));
		return new DecoratorResult(serviceName, entry.ClassName, generated, location);
	}

	/// <summary>
	/// What refuses the entry, checked in order and stopping at the first check that finds something, since a later
	/// check reads what an earlier one guarantees; empty when the decorator can be written.
	/// </summary>
	private static DiagnosticInfo[] RefusalsOf(ObservedEntry entry, Compilation compilation)
		=> new Func<DiagnosticInfo[]>[]
			{
				() => MissingAnchors(entry, compilation),
				() => UnsupportedMembers(entry),
				() => UnreadableRefusals(entry),
				() => HooksWithoutOneMethod(entry),
				() => TakenDependencyNames(entry),
			}
			.Select(check => check())
			.FirstOrDefault(found => found.Length > 0) ?? [];

	private static DiagnosticInfo[] MissingAnchors(ObservedEntry entry, Compilation compilation)
		=> new[] { ResultTypeName, OidcErrorTypeName, AuthorizationResponseTypeName }
			.Where(anchor => compilation.GetTypeByMetadataName(anchor) == null)
			.Select(anchor => new DiagnosticInfo(AnchorNotFound, entry.Location, anchor))
			.ToArray();

	private static DiagnosticInfo[] UnsupportedMembers(ObservedEntry entry)
		=> entry.Methods
			.Where(method => ResultOf(method) == null)
			.Select(method => new DiagnosticInfo(
				UnsupportedMember, entry.Location, entry.Service.ToDisplayString(), method.Name))
			.ToArray();

	private static DiagnosticInfo[] UnreadableRefusals(ObservedEntry entry)
		=> entry.Methods
			.Where(method => RefusalReaderOf(entry.Kind, ResultOf(method)!) == null)
			.Select(method => new DiagnosticInfo(
				UnknownRefusal,
				entry.Location,
				entry.Service.ToDisplayString(),
				method.Name,
				ResultOf(method)!.ToDisplayString()))
			.ToArray();

	private static DiagnosticInfo[] HooksWithoutOneMethod(ObservedEntry entry)
	{
		if (!(entry.TagsRequest || entry.ObservesResult) || entry.Methods.Length == 1)
			return [];

		return
		[
			new DiagnosticInfo(HooksNeedOneMethod, entry.Location, entry.Service.ToDisplayString(), entry.Methods.Length),
		];
	}

	private static DiagnosticInfo[] TakenDependencyNames(ObservedEntry entry)
		=> entry.Dependencies
			.Where(dependency => DependencyName(dependency).Length == 0 ||
			                     ReservedNames.Contains(DependencyName(dependency)) ||
			                     entry.Dependencies.Count(other => DependencyName(other) == DependencyName(dependency)) > 1)
			.Select(dependency => new DiagnosticInfo(
				DependencyNameTaken,
				entry.Location,
				dependency.ToDisplayString(),
				entry.Service.ToDisplayString(),
				DependencyName(dependency)))
			.ToArray();

	private static string Render(ObservedEntry entry)
	{
		var source = new StringBuilder()
			.AppendLine("// <auto-generated/>")
			.AppendLine("#nullable enable")
			.AppendLine("// The tenant a span names is read from the multi-tenancy feature where it is in use")
			.AppendLine("#pragma warning disable ABXMT001")
			.AppendLine()
			.AppendLine($"namespace {TelemetryNamespace};")
			.AppendLine()
			.AppendLine("/// <summary>")
			.AppendLine($"/// Runs <see cref=\"{EscapeXml(entry.Service.ToDisplayString())}\"/> in a span of " +
			            WhatItRecords(entry.Kind))
			.AppendLine("/// </summary>")
			.AppendLine(
				$"internal sealed partial class {entry.ClassName} : {entry.Service.ToDisplayString(FullyQualifiedWithNullability)}")
			.AppendLine("{");

		AppendConstructor(source, entry);
		foreach (var property in entry.Members.OfType<IPropertySymbol>())
			AppendProperty(source, property);

		foreach (var method in entry.Methods)
			AppendMethod(source, entry, method);

		return source.AppendLine("}").ToString();
	}

	private static DecoratorResult Refused(
		string service,
		string className,
		LocationInfo location,
		params DiagnosticInfo[] diagnostics)
		=> new(
			service,
			className,
			new GenerationResult($"{className}.g.cs", null, new EquatableArray<DiagnosticInfo>(diagnostics)),
			location);

	private static void AppendConstructor(StringBuilder source, ObservedEntry entry)
	{
		var serviceType = entry.Service.ToDisplayString(FullyQualifiedWithNullability);
		var observesEndpoint = MeasuresRequest(entry.Kind);

		source.AppendLine($"\tprivate readonly {serviceType} _inner;");
		foreach (var dependency in entry.Dependencies)
		{
			source.AppendLine(
				$"\tprivate readonly {dependency.ToDisplayString(FullyQualifiedWithNullability)} _{DependencyName(dependency)};");
		}

		if (observesEndpoint)
		{
			source
				.AppendLine($"\tprivate readonly global::{TelemetryNamespace}.OidcInstruments _instruments;")
				.AppendLine("\tprivate readonly global::Abblix.Oidc.Server.Features.MultiTenancy.ITenantAccessor? _tenants;");
		}

		var parameters = new List<string> { $"{serviceType} inner" };
		parameters.AddRange(entry.Dependencies.Select(dependency =>
			$"{dependency.ToDisplayString(FullyQualifiedWithNullability)} {Escape(DependencyName(dependency))}"));
		if (observesEndpoint)
		{
			parameters.Add($"global::{TelemetryNamespace}.OidcInstruments instruments");
			parameters.Add("global::Abblix.Oidc.Server.Features.MultiTenancy.ITenantAccessor? tenants = null");
		}

		source
			.AppendLine()
			.AppendLine($"\tpublic {entry.ClassName}(")
			.AppendLine("\t\t" + string.Join(",\n\t\t", parameters) + ")")
			.AppendLine("\t{")
			.AppendLine("\t\t_inner = inner;");
		foreach (var dependency in entry.Dependencies)
			source.AppendLine($"\t\t_{DependencyName(dependency)} = {Escape(DependencyName(dependency))};");

		if (observesEndpoint)
		{
			source
				.AppendLine("\t\t_instruments = instruments;")
				.AppendLine("\t\t_tenants = tenants;");
		}

		source
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

	private static void AppendMethod(StringBuilder source, ObservedEntry entry, IMethodSymbol method)
	{
		var result = ResultOf(method)!;
		var resultType = result.ToDisplayString(FullyQualifiedWithNullability);
		var parameters = string.Join(", ", method.Parameters.Select(parameter =>
			$"{parameter.Type.ToDisplayString(FullyQualifiedWithNullability)} {Escape(parameter.Name)}"));
		var arguments = string.Join(", ", method.Parameters.Select(parameter => Escape(parameter.Name)));
		var name = SymbolDisplay.FormatLiteral(entry.Name, quote: true);
		var reader = RefusalReaderOf(entry.Kind, result)!;
		var tagsRequest = entry.TagsRequest;
		var observesResult = entry.ObservesResult;

		var run = new StringBuilder();
		switch (entry.Kind)
		{
			case ObservationKind.Endpoint:
				run
					.Append($"global::{TelemetryNamespace}.EndpointObservation.RunAsync(")
					.Append($"{name}, _instruments, _tenants, () => _inner.{Escape(method.Name)}({arguments}), ")
					.Append($"global::{TelemetryNamespace}.EndpointObservation.{reader}");
				if (tagsRequest)
					run.Append($", () => RequestTagOf({arguments})");
				break;

			case ObservationKind.Stage:
				run
					.Append($"global::{TelemetryNamespace}.StageObservation.RunAsync(")
					.Append($"{name}, () => _inner.{Escape(method.Name)}({arguments}), ")
					.Append($"global::{TelemetryNamespace}.StageObservation.{reader}");
				break;

			default:
				throw new ArgumentOutOfRangeException(nameof(entry), entry.Kind, "The kind of observation is not known");
		}

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
				.AppendLine($"\t\tvar __result = await {run};")
				.AppendLine("\t\tObserve(__result);")
				.AppendLine("\t\treturn __result;")
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
	/// The end of the generated decorator's summary, naming what it records.
	/// </summary>
	private static string WhatItRecords(ObservationKind kind)
	{
		switch (kind)
		{
			case ObservationKind.Endpoint:
				return "its endpoint and measures it.";

			case ObservationKind.Stage:
				return "its stage.";

			default:
				throw new ArgumentOutOfRangeException(nameof(kind), kind, "The kind of observation is not known");
		}
	}

	/// <summary>
	/// Whether the decorator records the request into the server's metrics, for which it takes the instruments and the
	/// tenant accessor.
	/// </summary>
	private static bool MeasuresRequest(ObservationKind kind)
	{
		switch (kind)
		{
			case ObservationKind.Endpoint:
				return true;

			case ObservationKind.Stage:
				return false;

			default:
				throw new ArgumentOutOfRangeException(nameof(kind), kind, "The kind of observation is not known");
		}
	}

	/// <summary>
	/// The member of the observation of <paramref name="kind"/> that reads whether a result refuses, or null for a
	/// result whose refusal it cannot read.
	/// </summary>
	private static string? RefusalReaderOf(ObservationKind kind, ITypeSymbol result)
	{
		switch (kind)
		{
			case ObservationKind.Endpoint:
				return ErrorOf(result);

			case ObservationKind.Stage:
				return StageRefusalOf(result);

			default:
				throw new ArgumentOutOfRangeException(nameof(kind), kind, "The kind of observation is not known");
		}
	}

	/// <summary>
	/// The member of the stage observation that tells whether a result refuses, or null for a nullable Result, whose
	/// refusal sits behind the nullable. A stage reads only whether its result refuses, so a Result of any error does.
	/// </summary>
	private static string? StageRefusalOf(ITypeSymbol result)
	{
		if (result is INamedTypeSymbol { IsGenericType: true } wrapped &&
		    MetadataName(wrapped.OriginalDefinition) == NullableTypeName)
		{
			return IsResult(wrapped.TypeArguments[0]) ? null : StageRefusalOf(wrapped.TypeArguments[0]);
		}

		if (IsResult(result) || IsAuthorizationResponse(result))
			return "Refused";

		return "NeverRefused";
	}

	private static bool IsResult(ITypeSymbol type)
		=> type is INamedTypeSymbol { IsGenericType: true } named &&
		   MetadataName(named.OriginalDefinition) == ResultTypeName;

	private static bool IsAuthorizationResponse(ITypeSymbol type)
	{
		for (var current = type; current != null; current = current.BaseType)
		{
			if (MetadataName(current) == AuthorizationResponseTypeName)
				return true;
		}

		return false;
	}

	/// <summary>
	/// The member of the endpoint observation that tells the error a result refuses its request with, or null for a
	/// result that refuses with an error the observation cannot read.
	/// </summary>
	private static string? ErrorOf(ITypeSymbol result)
	{
		// A nullable Result hides its refusal behind the nullable, where the observation does not read it; any other
		// nullable value refuses exactly as the value does
		if (result is INamedTypeSymbol { IsGenericType: true } wrapped &&
		    MetadataName(wrapped.OriginalDefinition) == NullableTypeName)
		{
			var value = wrapped.TypeArguments[0];
			if (value is INamedTypeSymbol { IsGenericType: true } inner &&
			    MetadataName(inner.OriginalDefinition) == ResultTypeName)
			{
				return null;
			}

			return ErrorOf(value);
		}

		if (result is INamedTypeSymbol { IsGenericType: true } named &&
		    MetadataName(named.OriginalDefinition) == ResultTypeName)
		{
			return MetadataName(named.TypeArguments[1]) == OidcErrorTypeName ? "ErrorOf" : null;
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
		// A type named by the prefix alone leaves nothing, which the entry is refused for rather than named by
		var name = StripInterfacePrefix(dependency.Name);
		if (name.Length == 0)
			return name;

		return char.ToLowerInvariant(name[0]) + name.Substring(1);
	}

	private static string Escape(string identifier)
		=> SyntaxFacts.GetKeywordKind(identifier) != SyntaxKind.None ? "@" + identifier : identifier;

	private static string EscapeXml(string text)
		=> text.Replace("<", "{").Replace(">", "}");
}
