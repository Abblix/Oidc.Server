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

using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Abblix.Oidc.Server.Mvc.SourceGeneration;

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
	private const string GeneratedFromAttributeName = "Abblix.Oidc.Server.Mvc.Attributes.GeneratedFromAttribute";
	private const string BindsAttributeName = "Abblix.Oidc.Server.Mvc.Attributes.BindsAttribute";
	private const string MvcAttributesNamespace = "Abblix.Oidc.Server.Mvc.Attributes";
	private const string DeclarativeValidationNamespace = "Abblix.Oidc.Server.DeclarativeValidation";
	private const string SystemTextJsonNamespace = "System.Text.Json.Serialization";
	private const string CompilerServicesNamespace = "System.Runtime.CompilerServices";

	private static readonly SymbolDisplayFormat FullyQualifiedWithNullability =
		SymbolDisplayFormat.FullyQualifiedFormat.AddMiscellaneousOptions(
			SymbolDisplayMiscellaneousOptions.IncludeNullableReferenceTypeModifier);

	private static readonly DiagnosticDescriptor CoreTypeNotFound = new(
		id: "ABXG001",
		title: "Core model type not found",
		messageFormat: "The core model type '{0}' referenced by the generation stub could not be resolved",
		category: "Abblix.Oidc.Server.Mvc.SourceGeneration",
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor MarkerWithoutBinder = new(
		id: "ABXG002",
		title: "Wire-format marker has no binder",
		messageFormat: "The declarative marker '{0}' on '{1}.{2}' is realised by no model binder: " +
		               "no binder in this assembly declares it via [Binds], and no executable attribute " +
		               "with the same name exists in '" + MvcAttributesNamespace + "'. " +
		               "The parameter would silently stop binding.",
		category: "Abblix.Oidc.Server.Mvc.SourceGeneration",
		defaultSeverity: DiagnosticSeverity.Error,
		isEnabledByDefault: true);

	private static readonly DiagnosticDescriptor WireNameMissing = new(
		id: "ABXG003",
		title: "Bound property has no wire name",
		messageFormat: "The core property '{0}.{1}' declares no wire-level parameter name and is not excluded " +
		               "from serialization, so the generator cannot emit a binding for it",
		category: "Abblix.Oidc.Server.Mvc.SourceGeneration",
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
			.Any(static argument => argument is { Key: "SupportsGet", Value.Value: true });

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

		return new ModelEmitter(stub, coreType, compilation).Emit();
	}

	/// <summary>
	/// Renders one MVC model from its core counterpart. The inputs that stay constant across the
	/// whole rendering — the stub, the core type, the compilation, the binder map and the
	/// accumulating output — live as fields so the per-property and per-attribute steps receive
	/// only what varies between calls.
	/// </summary>
	private sealed class ModelEmitter(StubInfo stub, INamedTypeSymbol coreType, Compilation compilation)
	{
		private readonly StringBuilder writer = new();
		private readonly List<DiagnosticInfo> diagnostics = [];
		private readonly List<string> mappedProperties = [];
		private readonly Dictionary<string, INamedTypeSymbol> binderMap = BuildBinderMap(compilation);

		public GenerationResult Emit()
		{
			writer.AppendLine("// <auto-generated/>");
			writer.AppendLine($"// Generated by Abblix.Oidc.Server.Mvc.SourceGeneration from {coreType.ToDisplayString()}.");
			writer.AppendLine("#nullable enable");
			writer.AppendLine();
			writer.AppendLine($"namespace {stub.Namespace};");
			writer.AppendLine();
			writer.AppendLine($"public partial record {stub.Name}");
			writer.AppendLine("{");

			foreach (var property in CollectProperties(coreType))
			{
				if (!IsExcludedFromWire(property))
					EmitProperty(property);
			}

			EmitProjection();
			writer.AppendLine("}");

			return new GenerationResult(
				$"{stub.Namespace}.{stub.Name}.g.cs",
				writer.ToString(),
				new EquatableArray<DiagnosticInfo>([.. diagnostics]));
		}

		private void EmitProperty(IPropertySymbol property)
		{
			var wireName = GetWireName(property);
			if (wireName == null)
			{
				diagnostics.Add(new DiagnosticInfo(
					WireNameMissing, stub.Location, coreType.ToDisplayString(), property.Name));
				return;
			}

			if (mappedProperties.Count > 0)
				writer.AppendLine();

			writer.AppendLine($"\t/// <inheritdoc cref=\"{coreType.ToDisplayString()}.{property.Name}\"/>");

			var supportsGet = stub.SupportsGet ? "SupportsGet = true, " : string.Empty;
			writer.AppendLine(
				$"\t[global::Microsoft.AspNetCore.Mvc.BindProperty({supportsGet}Name = \"{wireName}\")]");

			foreach (var attribute in property.GetAttributes())
			{
				EmitPropertyAttribute(attribute, property);
			}

			var type = property.Type.ToDisplayString(FullyQualifiedWithNullability);
			writer.AppendLine($"\tpublic {type} {property.Name} {{ get; init; }}{GetInitializer(property)}");

			mappedProperties.Add(property.Name);
		}

		private void EmitPropertyAttribute(AttributeData attribute, IPropertySymbol property)
		{
			var attributeClass = attribute.AttributeClass;
			if (attributeClass == null)
				return;

			var attributeNamespace = attributeClass.ContainingNamespace.ToDisplayString();
			switch (attributeNamespace)
			{
				// Serialization metadata drives the core's JSON shape; the generated model is bound
				// from form/query values, where the wire name moves to BindProperty and the value
				// conversion to a model binder.
				case SystemTextJsonNamespace:
				// Compiler-synthesised attributes (NullableAttribute, ...) are reserved for the
				// compiler and cannot be written by hand; nullability is already carried by
				// #nullable enable plus the type's own annotations.
				case CompilerServicesNamespace:
					return;

				case DeclarativeValidationNamespace
					when binderMap.TryGetValue(attributeClass.ToDisplayString(), out var binder):
					writer.AppendLine(
						$"\t[global::Microsoft.AspNetCore.Mvc.ModelBinder(typeof({binder.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)}))]");
					return;

				case DeclarativeValidationNamespace:
				{
					// A declarative core attribute is either a wire-format marker realised by a binder
					// (handled above) or a validation marker mirrored by an executable MVC attribute
					// with the same name. Anything else is a silent-drop hazard, so fail the build.
					var executable = compilation.GetTypeByMetadataName(
						$"{MvcAttributesNamespace}.{attributeClass.MetadataName}");
					if (executable != null)
					{
						writer.AppendLine(
							$"\t{RenderAttribute(attribute, executable.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))}");
						return;
					}

					diagnostics.Add(new DiagnosticInfo(
						MarkerWithoutBinder, stub.Location,
						attributeClass.Name, coreType.ToDisplayString(), property.Name));
					return;
				}

				default:
					writer.AppendLine($"\t{RenderAttribute(attribute, attributeClass.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat))}");
					return;
			}
		}

		private void EmitProjection()
		{
			var coreTypeName = coreType.ToDisplayString(FullyQualifiedWithNullability);

			writer.AppendLine();
			writer.AppendLine("\t/// <summary>");
			writer.AppendLine("\t/// Implicitly projects the transport-bound model onto its core counterpart, copying every");
			writer.AppendLine("\t/// bound parameter so the core pipeline operates on a transport-agnostic shape.");
			writer.AppendLine("\t/// </summary>");
			writer.AppendLine($"\tpublic static implicit operator {coreTypeName}({stub.Name} request) => new()");
			writer.AppendLine("\t{");

			foreach (var name in mappedProperties)
			{
				writer.AppendLine($"\t\t{name} = request.{name},");
			}

			writer.AppendLine("\t};");
		}
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

	private static bool IsExcludedFromWire(IPropertySymbol property)
		=> property.GetAttributes().Any(static attribute =>
			attribute.AttributeClass is { Name: "JsonIgnoreAttribute" } attributeClass &&
			attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace);

	private static string? GetWireName(IPropertySymbol property)
	{
		foreach (var attribute in property.GetAttributes())
		{
			if (attribute.AttributeClass is { Name: "JsonPropertyNameAttribute" } attributeClass &&
			    attributeClass.ContainingNamespace.ToDisplayString() == SystemTextJsonNamespace &&
			    attribute.ConstructorArguments is [{ Value: string wireName }])
			{
				return wireName;
			}
		}

		return null;
	}

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
			foreach (var property in current.GetMembers().OfType<IPropertySymbol>())
			{
				// Compiler-synthesised record members (EqualityContract) read from a metadata
				// reference are not flagged as implicitly declared, so accessibility and the
				// CompilerGenerated marker filter them out instead.
				if (property.IsStatic ||
				    property.IsImplicitlyDeclared ||
				    property.DeclaredAccessibility != Accessibility.Public ||
				    HasCompilerGeneratedAttribute(property) ||
				    !seen.Add(property.Name))
					continue;

				yield return property;
			}
		}
	}

	private static bool HasCompilerGeneratedAttribute(ISymbol symbol)
		=> symbol.GetAttributes().Any(static attribute =>
			attribute.AttributeClass is { Name: "CompilerGeneratedAttribute" } attributeClass &&
			attributeClass.ContainingNamespace.ToDisplayString() == CompilerServicesNamespace);

	private static Dictionary<string, INamedTypeSymbol> BuildBinderMap(Compilation compilation)
	{
		var map = new Dictionary<string, INamedTypeSymbol>();

		foreach (var type in GetAllTypes(compilation.Assembly.GlobalNamespace))
		{
			foreach (var attribute in type.GetAttributes())
			{
				if (attribute.AttributeClass?.ToDisplayString() == BindsAttributeName &&
				    attribute.ConstructorArguments is [{ Value: INamedTypeSymbol marker }])
				{
					map[marker.ToDisplayString()] = type;
				}
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
