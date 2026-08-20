// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.SourceGenerators.Mvc;

/// <summary>
/// Generates MVC binding models from the core request models. A hand-written partial record stub
/// marked with the trigger attribute names its core counterpart; the generator emits the matching
/// partial with bound properties, model binders resolved from the core wire-format markers via
/// the binder self-declarations, validation attributes translated to their executable MVC
/// counterparts, and the mapping method projecting the bound model back onto the core type.
/// </summary>
[Generator]
public class MvcModelGenerator : IIncrementalGenerator
{
	// The generator targets netstandard2.0 and analyses the net8+ Abblix assemblies and the
	// System.Text.Json serialization attributes through compilation symbols only, so it cannot
	// reference those types for nameof/typeof - their identities are mirrored here as constants.
	// A marker renamed on the core side does not drift silently: an unrecognised declarative
	// marker on a payload-excluded property fails the build (see Emit).
	private const string GeneratedFromAttributeName = "Abblix.Oidc.Server.Mvc.Attributes.GeneratedFromAttribute";
	private const string BindsAttributeName = "Abblix.Oidc.Server.Mvc.Attributes.BindsAttribute";
	private const string SupportsGetPropertyName = "SupportsGet";

	// The executable validation attributes live in a referenced assembly and are emitted by their resolved symbol
	// (see EmitPropertyAttribute); this one anchors the resolution of their shared namespace, so a namespace move
	// follows the type instead of leaving a stale lookup key here. The anchor has to be an attribute this library
	// owns outright and the framework has no equivalent of: a name the framework also declares would keep
	// resolving from there if ours were removed, and the namespace derived from it would be the framework's.
	private const string ValidationAttributeAnchor = "Abblix.Utils.Validation.AbsoluteUriAttribute";
	// The namespace of the declarative binding markers is resolved from this anchor marker rather than hardcoded,
	// so renaming or moving the marker namespace fails the generation loud instead of silently making every
	// marker-namespace match fall through and dropping the bindings.
	private const string DeclarativeMarkerAnchor = "Abblix.Oidc.Server.DeclarativeBinding.SpaceSeparatedStringAttribute";
	private const string RequestHeaderMarkerName = "RequestHeaderAttribute";
	private const string AuthorizationHeaderMarkerName = "AuthorizationHeaderAttribute";
	private const string ClientCertificateMarkerName = "ClientCertificateAttribute";
	private const string SystemTextJsonNamespace = "System.Text.Json.Serialization";
	private const string JsonIgnoreAttributeName = "JsonIgnoreAttribute";
	private const string JsonPropertyNameAttributeName = "JsonPropertyNameAttribute";

	private static readonly string CompilerServicesNamespace =
		typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute).Namespace!;

	// Taken from the type rather than written out, so it cannot rot into a dangling emitted reference.
	private static readonly string ExcludeFromCoverageAttribute =
		$"global::{typeof(System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverageAttribute).FullName}";

	private static readonly SymbolDisplayFormat FullyQualifiedWithNullability =
		SymbolDisplayFormat.FullyQualifiedFormat.AddMiscellaneousOptions(
			SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier);

	private const string DiagnosticCategory = "Abblix.Oidc.Server.SourceGenerators.Mvc";

		private static readonly DiagnosticDescriptor CoreTypeNotFound = new(
		id: "ABXG001",
		title: "Core model type not found",
		messageFormat: "The core model type '{0}' referenced by the generation stub could not be resolved",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor MarkerWithoutBinder = new(
		id: "ABXG002",
		title: "Wire-format marker has no binder",
		messageFormat: "The declarative marker '{0}' on '{1}.{2}' is realised by no model binder: " +
		               "no binder in this assembly declares it via [Binds], and no executable attribute " +
		               "with the same name exists in the validation-attributes namespace. " +
		               "The parameter would silently stop binding.",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor WireNameMissing = new(
		id: "ABXG003",
		title: "Bound property has no wire name",
		messageFormat: "The core property '{0}.{1}' declares no wire-level parameter name and is not excluded " +
		               "from serialization, so the generator cannot emit a binding for it",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor MarkerNamespaceNotFound = new(
		id: "ABXG004",
		title: "Declarative marker namespace not found",
		messageFormat: "The declarative marker anchor '{0}' could not be resolved, so the generator cannot tell " +
		               "which attributes are binding markers - it was renamed or moved and every marker would " +
		               "silently stop binding",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor SupportsGetPropertyMissing = new(
		id: "ABXG005",
		title: "SupportsGet property not found on the trigger attribute",
		messageFormat: "The generator reads the '{0}' flag off '{1}' by name, but that attribute declares no such " +
		               "boolean property, so it was renamed and GET support would silently stop working",
		category: DiagnosticCategory,
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	/// <inheritdoc />
	public void Initialize(IncrementalGeneratorInitializationContext context)
	{
		var stubs = context.SyntaxProvider.ForAttributeWithMetadataName(
			GeneratedFromAttributeName,
			predicate: static (node, _) => node is RecordDeclarationSyntax,
			transform: static (ctx, _) => ExtractStub(ctx));

		// The compilation joins the pipeline here, but the projected GenerationResult is a pure
		// value (strings + diagnostics data), so the driver re-renders a model only when its
		// inputs actually changed and skips AddSource for identical outputs.
		var outputs = stubs
			.Combine(context.CompilationProvider)
			.Select(static (pair, _) => Generate(pair.Left, pair.Right));

		context.RegisterSourceOutput(outputs, static (productionContext, result) =>
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

	private static StubInfo ExtractStub(GeneratorAttributeSyntaxContext context)
	{
		var stubType = (INamedTypeSymbol)context.TargetSymbol;
		var attribute = context.Attributes[0];

		var coreTypeName = attribute.ConstructorArguments is [{ Value: INamedTypeSymbol coreType } _]
			? $"{coreType.ContainingNamespace.ToDisplayString()}.{coreType.MetadataName}"
			: string.Empty;

		var supportsGet = attribute.NamedArguments
			.Any(static argument => argument is { Key: SupportsGetPropertyName, Value.Value: true });

		return new StubInfo(
			stubType.ContainingNamespace.ToDisplayString(),
			stubType.Name,
			coreTypeName,
			supportsGet,
			LocationInfo.From(context.TargetNode.GetLocation()));
	}

	private static GenerationResult Generate(StubInfo stub, Compilation compilation)
	{
		var coreType = compilation.GetTypeByMetadataName(stub.CoreTypeName);
		if (coreType == null)
		{
			return new GenerationResult(
				$"{stub.Namespace}.{stub.Name}.g.cs",
				null,
				new EquatableArray<DiagnosticInfo>([new DiagnosticInfo(CoreTypeNotFound, stub.Location, stub.CoreTypeName)]));
		}

		// Resolve the declarative-marker namespace from its anchor so a rename fails loud here rather than
		// silently unmatching every marker in the emitter below.
		var declarativeAnchor = compilation.GetTypeByMetadataName(DeclarativeMarkerAnchor);
		if (declarativeAnchor == null)
		{
			return new GenerationResult(
				$"{stub.Namespace}.{stub.Name}.g.cs",
				null,
				new EquatableArray<DiagnosticInfo>([new DiagnosticInfo(MarkerNamespaceNotFound, stub.Location, DeclarativeMarkerAnchor)]));
		}

		// The generator reads the SupportsGet flag off the trigger attribute by name; verify that boolean property
		// still exists so a rename fails loud rather than silently dropping GET support.
		var generatedFrom = compilation.GetTypeByMetadataName(GeneratedFromAttributeName);
		if (generatedFrom == null || !HasBooleanProperty(generatedFrom, SupportsGetPropertyName))
		{
			return new GenerationResult(
				$"{stub.Namespace}.{stub.Name}.g.cs",
				null,
				new EquatableArray<DiagnosticInfo>([new DiagnosticInfo(
					SupportsGetPropertyMissing, stub.Location, SupportsGetPropertyName, GeneratedFromAttributeName)]));
		}

		return new ModelEmitter(stub, coreType, compilation, declarativeAnchor.ContainingNamespace.ToDisplayString()).Emit();
	}

	private static bool HasBooleanProperty(INamedTypeSymbol type, string name)
		=> type.GetMembers(name).OfType<IPropertySymbol>().Any(property => property.Type.SpecialType == SpecialType.System_Boolean);

	/// <summary>
	/// Renders one MVC model from its core counterpart. The inputs that stay constant across the
	/// whole rendering - the stub, the core type, the compilation, the binder map and the
	/// accumulating output - live as fields so the per-property and per-attribute steps receive
	/// only what varies between calls.
	/// </summary>
	private sealed class ModelEmitter(
			StubInfo stub, INamedTypeSymbol coreType, Compilation compilation, string declarativeNamespace)
	{
		private readonly StringBuilder _writer = new();
		private readonly List<DiagnosticInfo> _diagnostics = [];
		private readonly List<string> _mappedProperties = [];
		private readonly Dictionary<string, INamedTypeSymbol> _binderMap = BuildBinderMap(compilation);

		// The namespace the executable validation attributes live in, derived from the anchor type rather than
		// hardcoded, so the twin lookup below follows the attributes if they move. Null only if the anchor is
		// absent, in which case any validation marker fails loud through MarkerWithoutBinder.
		private readonly string? _validationNamespace =
			compilation.GetTypeByMetadataName(ValidationAttributeAnchor)?.ContainingNamespace.ToDisplayString();

		// Resolved once in Generate and passed in; the marker-match gates compare against it rather than a
		// hardcoded namespace so a rename of the marker namespace fails loud instead of silently unmatching.
		private readonly string _declarativeNamespace = declarativeNamespace;

		public GenerationResult Emit()
		{
			_writer.AppendLine("// <auto-generated/>");
			_writer.AppendLine($"// Generated by Abblix.Oidc.Server.SourceGenerators.Mvc from {coreType.ToDisplayString()}.");
			_writer.AppendLine("#nullable enable");
			_writer.AppendLine();
			_writer.AppendLine($"namespace {stub.Namespace};");
			_writer.AppendLine();
			// Nobody writes this file, so counting its lines tells nobody anything: it drags the adapter's
			// coverage denominator down with code that can only be changed by changing the generator, and
			// hides the hand-written shortfall behind it. The attribute travels with the source rather than
			// living in a coverage settings file, which is both tool-independent and the only route that
			// works here - dotnet test refuses to run at all when handed --coverage-settings.
			_writer.AppendLine($"[{ExcludeFromCoverageAttribute}]");
			_writer.AppendLine($"public partial record {stub.Name}");
			_writer.AppendLine("{");

			foreach (var property in CollectProperties(coreType))
			{
				// A transport-source marker overrides the JSON exclusion: such properties are not
				// wire payload parameters, yet they are bound - from a header or the TLS connection.
				var sourceMarker = TryGetSourceMarker(property);
				if (sourceMarker != null)
				{
					EmitSourceProperty(property, sourceMarker);
				}
				else if (IsExcludedFromWire(property))
				{
					// A payload-excluded property carrying a declarative marker the generator does
					// not recognise would silently fall out of the model - fail the build instead,
					// so a renamed or mistyped marker cannot drop a parameter unnoticed.
					if (HasDeclarativeMarker(property))
					{
						_diagnostics.Add(new DiagnosticInfo(
							MarkerWithoutBinder, stub.Location,
							"unrecognised", coreType.ToDisplayString(), property.Name));
					}
				}
				else
				{
					EmitProperty(property);
				}
			}

			EmitProjection();
			_writer.AppendLine("}");

			return new GenerationResult(
				$"{stub.Namespace}.{stub.Name}.g.cs",
				_writer.ToString(),
				new EquatableArray<DiagnosticInfo>([.. _diagnostics]));
		}

		private void EmitSourceProperty(IPropertySymbol property, AttributeData sourceMarker)
		{
			if (_mappedProperties.Count > 0)
				_writer.AppendLine();

			_writer.AppendLine($"\t/// <inheritdoc cref=\"{coreType.ToDisplayString()}.{property.Name}\"/>");

			var markerClass = sourceMarker.AttributeClass!;
			switch (markerClass.Name)
			{
				case RequestHeaderMarkerName
					when sourceMarker.ConstructorArguments is [{ Value: string headerName }]:
					_writer.AppendLine(
						$"\t[global::Microsoft.AspNetCore.Mvc.FromHeader(Name = {Microsoft.CodeAnalysis.CSharp.SymbolDisplay.FormatLiteral(headerName, quote: true)})]");
					break;

				case AuthorizationHeaderMarkerName
					when _binderMap.TryGetValue(markerClass.ToDisplayString(), out var headerBinder):
					// "Authorization" is the standard HTTP header name implied by the marker's
					// semantics (RFC 9110 §11.6.2), not binder-specific knowledge.
					_writer.AppendLine(
						$"\t[global::Microsoft.AspNetCore.Mvc.ModelBinder(typeof({headerBinder.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}), Name = \"Authorization\")]");
					break;

				case ClientCertificateMarkerName
					when _binderMap.TryGetValue(markerClass.ToDisplayString(), out var certificateBinder):
					_writer.AppendLine(
						$"\t[global::Microsoft.AspNetCore.Mvc.ModelBinder(typeof({certificateBinder.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}))]");
					break;

				default:
					_diagnostics.Add(new DiagnosticInfo(
						MarkerWithoutBinder, stub.Location,
						markerClass.Name, coreType.ToDisplayString(), property.Name));
					return;
			}

			var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);
			_writer.AppendLine($"\tpublic {type} {property.Name} {{ get; init; }}{GetInitializer(property)}");

			_mappedProperties.Add(property.Name);
		}

		private void EmitProperty(IPropertySymbol property)
		{
			var wireName = GetWireName(property);
			if (wireName == null)
			{
				_diagnostics.Add(new DiagnosticInfo(
					WireNameMissing, stub.Location, coreType.ToDisplayString(), property.Name));
				return;
			}

			if (_mappedProperties.Count > 0)
				_writer.AppendLine();

			_writer.AppendLine($"\t/// <inheritdoc cref=\"{coreType.ToDisplayString()}.{property.Name}\"/>");

			var supportsGet = stub.SupportsGet ? "SupportsGet = true, " : string.Empty;
			_writer.AppendLine(
				$"\t[global::Microsoft.AspNetCore.Mvc.BindProperty({supportsGet}Name = \"{wireName}\")]");

			foreach (var attribute in property.GetAttributes())
			{
				EmitPropertyAttribute(attribute, property);
			}

			var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);
			_writer.AppendLine($"\tpublic {type} {property.Name} {{ get; init; }}{GetInitializer(property)}");

			_mappedProperties.Add(property.Name);
		}

		private void EmitPropertyAttribute(AttributeData attribute, IPropertySymbol property)
		{
			var attributeClass = attribute.AttributeClass;
			if (attributeClass == null)
				return;

			var attributeNamespace = attributeClass.ContainingNamespace.ToDisplayString();

			// Serialization metadata drives the core's JSON shape; the generated model is bound
			// from form/query values, where the wire name moves to BindProperty and the value
			// conversion to a model binder. Compiler-synthesised attributes (NullableAttribute, ...)
			// are reserved for the compiler and cannot be written by hand; nullability is already
			// carried by #nullable enable plus the type's own annotations.
			if (attributeNamespace == SystemTextJsonNamespace || attributeNamespace == CompilerServicesNamespace)
				return;

			switch (attributeNamespace)
			{
				case { } when attributeNamespace == _declarativeNamespace
					&& _binderMap.TryGetValue(attributeClass.ToDisplayString(), out var binder):
					_writer.AppendLine(
						$"\t[global::Microsoft.AspNetCore.Mvc.ModelBinder(typeof({binder.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}))]");
					return;

				case { } when attributeNamespace == _declarativeNamespace:
				{
					// A declarative core attribute is either a wire-format marker realised by a binder
					// (handled above) or a validation marker mirrored by an executable MVC attribute
					// with the same name. Anything else is a silent-drop hazard, so fail the build.
					var executable = ExecutableTwins.Resolve(
							compilation, _validationNamespace, attributeClass.MetadataName);
					if (executable != null)
					{
						_writer.AppendLine(
							$"\t{RenderAttribute(attribute, executable.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))}");
						return;
					}

					_diagnostics.Add(new DiagnosticInfo(
						MarkerWithoutBinder, stub.Location,
						attributeClass.Name, coreType.ToDisplayString(), property.Name));
					return;
				}

				default:
					_writer.AppendLine($"\t{RenderAttribute(attribute, attributeClass.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))}");
					return;
			}
		}

		private void EmitProjection()
		{
			var coreTypeName = coreType.ToDisplayString(FullyQualifiedWithNullability);

			_writer.AppendLine();
			_writer.AppendLine("\t/// <summary>");
			_writer.AppendLine("\t/// Projects the transport-bound model onto its core counterpart, copying every bound");
			_writer.AppendLine("\t/// parameter so the core pipeline operates on a transport-agnostic shape.");
			_writer.AppendLine("\t/// </summary>");
			_writer.AppendLine($"\tpublic {coreTypeName} Map() => new()");
			_writer.AppendLine("\t{");

			foreach (var name in _mappedProperties)
			{
				_writer.AppendLine($"\t\t{name} = {name},");
			}

			_writer.AppendLine("\t};");
			_writer.AppendLine();
			_writer.AppendLine("\t/// <summary>");
			_writer.AppendLine($"\t/// Implicit form of <see cref=\"Map\"/>, letting a bound model flow into any");
			_writer.AppendLine("\t/// core-typed parameter or variable without an explicit call.");
			_writer.AppendLine("\t/// </summary>");
			_writer.AppendLine($"\tpublic static implicit operator {coreTypeName}({stub.Name} request) => request.Map();");
		}

		private static string RenderAttribute(AttributeData attribute, string fullyQualifiedName)
		{
			var arguments = TrimDefaultArguments(attribute)
				.Select(RenderConstructorArgument)
				.Concat(attribute.NamedArguments.Select(
					static named => $"{named.Key} = {RenderTypedConstant(named.Value)}"))
				.ToArray();

			return arguments.Length == 0
				? $"[{fullyQualifiedName}]"
				: $"[{fullyQualifiedName}({string.Join(", ", arguments)})]";
		}

		private static IEnumerable<TypedConstant> TrimDefaultArguments(AttributeData attribute)
		{
			var arguments = attribute.ConstructorArguments;
			var parameters = attribute.AttributeConstructor?.Parameters;
			var count = arguments.Length;

			// Optional constructor parameters the source never spelled out arrive from metadata folded
			// into explicit constructor arguments; rendering them back would couple the output to one
			// specific overload shape. Trailing arguments equal to their parameter's declared default
			// are therefore omitted, restoring the attribute as it reads in the core source.
			while (count > 0 &&
			       parameters is { } knownParameters &&
			       count <= knownParameters.Length &&
			       knownParameters[count - 1] is { HasExplicitDefaultValue: true } parameter &&
			       Equals(arguments[count - 1].Value, parameter.ExplicitDefaultValue))
			{
				count--;
			}

			for (var i = 0; i < count; i++)
			{
				yield return arguments[i];
			}
		}

		private static string RenderConstructorArgument(TypedConstant constant)
			// A trailing array constructor argument is rendered in expanded form on the assumption
			// of a params parameter, matching how the attribute reads in the core source.
			=> constant switch
			{
				{ Kind: TypedConstantKind.Array } => string.Join(", ", constant.Values.Select(RenderTypedConstant)),
				_ => RenderTypedConstant(constant)
			};

		private static string RenderTypedConstant(TypedConstant constant)
			=> constant switch
			{
				{ IsNull: true } => "null",

				{ Kind: TypedConstantKind.Type, Value: ITypeSymbol type }
					=> $"typeof({type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)})",

				{ Kind: TypedConstantKind.Enum, Type: { } enumType }
					=> $"({enumType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)})" +
					   Convert.ToString(constant.Value, System.Globalization.CultureInfo.InvariantCulture),

				{ Kind: TypedConstantKind.Array }
					=> $"new[] {{ {string.Join(", ", constant.Values.Select(RenderTypedConstant))} }}",

				{ Value: string text } => Microsoft.CodeAnalysis.CSharp.SymbolDisplay.FormatLiteral(text, quote: true),
				{ Value: char character } => Microsoft.CodeAnalysis.CSharp.SymbolDisplay.FormatLiteral(character, quote: true),
				{ Value: bool flag } => flag ? "true" : "false",

				_ => Convert.ToString(constant.Value, System.Globalization.CultureInfo.InvariantCulture) ?? "null",
			};

		private AttributeData? TryGetSourceMarker(IPropertySymbol property)
			=> property.GetAttributes().FirstOrDefault(attribute =>
				attribute.AttributeClass is
				{
					Name: RequestHeaderMarkerName or AuthorizationHeaderMarkerName or ClientCertificateMarkerName,
				} attributeClass &&
				attributeClass.ContainingNamespace.ToDisplayString() == _declarativeNamespace);

		private bool HasDeclarativeMarker(IPropertySymbol property)
			=> property.GetAttributes().Any(attribute =>
				attribute.AttributeClass?.ContainingNamespace.ToDisplayString() == _declarativeNamespace);

		private static bool IsExcludedFromWire(IPropertySymbol property)
			=> property.GetAttributes().Any(static attribute =>
				attribute.AttributeClass is { Name: JsonIgnoreAttributeName } attributeClass &&
				attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace);

		private static string? GetWireName(IPropertySymbol property)
			=> property.GetAttributes()
				.Where(static attribute =>
					attribute.AttributeClass is { Name: JsonPropertyNameAttributeName } attributeClass &&
					attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace)
				.Select(static attribute =>
					attribute.ConstructorArguments is [{ Value: string wireName }] ? wireName : null)
				.FirstOrDefault(static wireName => wireName != null);

		private static string GetInitializer(IPropertySymbol property)
		{
			if (property.Type is { IsReferenceType: true, NullableAnnotation: NullableAnnotation.NotAnnotated })
			{
				return property.Type.TypeKind == TypeKind.Array ? " = [];" : " = null!;";
			}

			return string.Empty;
		}

		private static IEnumerable<IPropertySymbol> CollectProperties(INamedTypeSymbol type)
		{
			var seen = new HashSet<string>();

			for (var current = type; current != null && current.SpecialType != SpecialType.System_Object;
			     current = current.BaseType)
			{
				// Compiler-synthesised record members (EqualityContract) read from a metadata
				// reference are not flagged as implicitly declared, so accessibility and the
				// CompilerGenerated marker filter them out instead. The name dedup keeps the most
				// derived declaration when the base chain hides or overrides a property.
				var declared = current.GetMembers()
					.OfType<IPropertySymbol>()
					.Where(static property =>
						property is { IsStatic: false, IsImplicitlyDeclared: false, DeclaredAccessibility: Accessibility.Public } &&
						!HasCompilerGeneratedAttribute(property))
					.Where(property => seen.Add(property.Name));

				foreach (var property in declared)
				{
					yield return property;
				}
			}
		}

		private static bool HasCompilerGeneratedAttribute(ISymbol symbol)
			=> symbol.GetAttributes().Any(static attribute =>
				attribute.AttributeClass is { Name: nameof(System.Runtime.CompilerServices.CompilerGeneratedAttribute) } attributeClass &&
				attributeClass.ContainingNamespace.ToDisplayString() == CompilerServicesNamespace);

		private static Dictionary<string, INamedTypeSymbol> BuildBinderMap(Compilation compilation)
		{
			var map = new Dictionary<string, INamedTypeSymbol>();

			foreach (var type in GetAllTypes(compilation.Assembly.GlobalNamespace))
			{
				var declarations = type.GetAttributes()
					.Where(static attribute => attribute.AttributeClass?.ToDisplayString() == BindsAttributeName);

				foreach (var declaration in declarations)
				{
					if (declaration.ConstructorArguments is [{ Value: INamedTypeSymbol marker }])
						map[marker.ToDisplayString()] = type;
				}
			}

			return map;
		}

		private static IEnumerable<INamedTypeSymbol> GetAllTypes(INamespaceSymbol namespaceSymbol)
		{
			foreach (var member in namespaceSymbol.GetMembers())
			{
				switch (member)
				{
					case INamespaceSymbol childNamespace:
						foreach (var type in GetAllTypes(childNamespace))
							yield return type;
						break;

					case INamedTypeSymbol type:
						yield return type;
						break;
				}
			}
		}
	}
}
