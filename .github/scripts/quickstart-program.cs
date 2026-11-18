#:package Microsoft.CodeAnalysis.CSharp@5.12.0

// Writes the Program.cs a reader of a README quickstart ends up with: the README block, taken from its compiled
// copy under tests/Abblix.DocSamples/Samples (ReadmeSampleTests holds each copy to its README's lines). The one
// line it adds is the distributed cache the repository README's outline paragraph leaves to the host, without
// which the server does not start; it goes once the server falls back to an in-process cache of its own. The
// release workflow builds the result in a project made by `dotnet new web`.
//
//   dotnet quickstart-program.cs <path to the compiled copy> <path of the Program.cs to write>
//
// The block is read as C# syntax, never as text: the statements between the copy's `// <sample>` and
// `// </sample>` markers become the top-level statements, and a statement of the method outside them is refused,
// since it would be code the reader never sees. The file pins its own Roslyn version, which the central package
// versions of this repository refuse, so the workflow copies it to an empty folder and runs it there.

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

if (args is not [var samplePath, var programPath])
{
    Console.Error.WriteLine("Usage: dotnet quickstart-program.cs <compiled copy of the block> <Program.cs to write>");
    return 2;
}

var tree = CSharpSyntaxTree.ParseText(File.ReadAllText(samplePath), path: samplePath);
var errors = tree.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToList();
if (errors.Count > 0)
{
    foreach (var error in errors)
        Console.Error.WriteLine(error);
    return 1;
}

var unit = tree.GetCompilationUnitRoot();
var configure = unit.DescendantNodes()
    .OfType<MethodDeclarationSyntax>()
    .Where(method => method is { Identifier.Text: "Configure", Body: not null })
    .ToList();
if (configure is not [{ Body: { } body }])
    return Fail($"{samplePath} declares {configure.Count} Configure methods with a body, where the copy of a quickstart has one");

var opening = Marker(body, "// <sample>");
var closing = Marker(body, "// </sample>");
if (opening is not [var start] || closing is not [var end] || end.SpanStart < start.Span.End)
{
    return Fail($"{samplePath} marks its sample with {opening.Count} '// <sample>' and {closing.Count} '// </sample>' "
                + "comments, where the copy of a quickstart has one of each, in that order");
}

var outside = body.Statements
    .Where(statement => statement.SpanStart < start.Span.End || statement.Span.End > end.SpanStart)
    .ToList();
if (outside.Count > 0)
{
    return Fail($"{samplePath} has {outside.Count} statements outside its sample markers, starting with "
                + $"'{outside[0]}', which a reader of the README would not have");
}

var statements = body.Statements.ToList();

// After the builder exists: services are registered before Build
var (builderAt, builder) = Declaration(statements, "CreateBuilder");
if (builderAt < 0)
    return Fail("The quickstart declares no variable initialized by WebApplication.CreateBuilder(...)");

statements.Insert(builderAt + 1, HostLine($"{builder}.Services.AddDistributedMemoryCache();"));

// Each node keeps its own comments and line breaks, so the file reads like the README block it came from
var program = string.Concat(unit.Usings.Select(directive => directive.WithoutLeadingTrivia().ToFullString()))
              + string.Concat(statements.Select(statement => statement.ToFullString()));

File.WriteAllText(programPath, program);
Console.WriteLine($"Wrote {programPath}:");
Console.WriteLine(program);
return 0;

static List<SyntaxTrivia> Marker(BlockSyntax body, string text)
    => body.DescendantTrivia()
        .Where(trivia => trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) && trivia.ToString().Trim() == text)
        .ToList();

// The index and name of the single variable whose initializer calls a method of that name, or -1 when none does
static (int Index, string Name) Declaration(List<StatementSyntax> statements, string method)
{
    for (var index = 0; index < statements.Count; index++)
    {
        if (statements[index] is LocalDeclarationStatementSyntax
            {
                Declaration.Variables: [
                {
                    Initializer.Value: InvocationExpressionSyntax
                    {
                        Expression: MemberAccessExpressionSyntax { Name.Identifier.Text: var name },
                    },
                } variable],
            } && name == method)
        {
            return (index, variable.Identifier.Text);
        }
    }

    return (-1, string.Empty);
}

static StatementSyntax HostLine(string code)
    => ParseStatement(code)
        .WithLeadingTrivia(LineFeed, Comment("// Added by the host, as the repository README's outline asks"), LineFeed)
        .WithTrailingTrivia(LineFeed);

static int Fail(string message)
{
    Console.Error.WriteLine(message);
    return 1;
}
