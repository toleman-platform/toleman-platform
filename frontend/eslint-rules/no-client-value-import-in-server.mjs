import fs from "node:fs";
import path from "node:path";

/**
 * Fails the build when a Server Component imports a non-component *value*
 * from a `"use client"` module (issue #206).
 *
 * Next replaces a client module's exports with client reference stubs when a
 * Server Component imports them. The failure mode differs by export kind, and
 * that asymmetry is what makes this worth a lint rule:
 *
 *   - A function fails loudly at request time: "Attempted to call X() from
 *     the server but X is on the client."
 *   - A constant fails SILENTLY. It becomes a stub object, and any code using
 *     it just quietly does the wrong thing.
 *
 * Both have already happened in this codebase:
 *
 *   #196  THEME_COOKIE_KEY was exported from theme-toggle.tsx ("use client")
 *         and used by both layouts as `cookies().get(THEME_COOKIE_KEY)`. The
 *         lookup silently returned undefined on every request, so light mode
 *         flashed dark on every load and the theme toggle's first click
 *         became a no-op. It survived until someone noticed the label was
 *         wrong after a reload.
 *   #204  pageSizeFromParams, same shape but a function, so it blew up
 *         immediately instead.
 *
 * The fix in both cases was the same: move the shared value into a plain
 * module (@/lib/theme, @/lib/pagination) and re-export it from the client
 * component for existing client importers. This rule exists so the third
 * occurrence is caught at lint time rather than in production.
 *
 * What is deliberately ALLOWED:
 *   - Importing a client *component* to render it. That is the normal
 *     composition model; `<ThemeToggle />` inside a server layout is correct.
 *     Detected by scope analysis: if every reference to the binding sits in
 *     JSX element-name position, it is a component import.
 *   - `import type` / type-only specifiers. Types are erased at compile time
 *     and never reach the runtime boundary.
 *   - Client-to-client imports. The rule only inspects files that are not
 *     themselves client modules.
 */

const CLIENT_DIRECTIVE = "use client";
const RESOLVE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"];

/** Does this file start with the "use client" directive? */
function isClientSource(source) {
  // The directive must be the first statement; a match anywhere else (a
  // comment, a string in the body) does not make the module a client module.
  const withoutLeadingTrivia = source.replace(/^(\s|\/\/[^\n]*\n|\/\*[\s\S]*?\*\/)*/, "");
  return (
    withoutLeadingTrivia.startsWith(`"${CLIENT_DIRECTIVE}"`) ||
    withoutLeadingTrivia.startsWith(`'${CLIENT_DIRECTIVE}'`)
  );
}

function readIfFile(candidate) {
  try {
    if (fs.statSync(candidate).isFile()) return fs.readFileSync(candidate, "utf8");
  } catch {
    /* not a file */
  }
  return null;
}

/** Resolve an import specifier to a source file, honouring the @/ alias. */
function resolveImport(specifier, fromFile, srcRoot) {
  let base;
  if (specifier.startsWith("@/")) {
    base = path.join(srcRoot, specifier.slice(2));
  } else if (specifier.startsWith(".")) {
    base = path.resolve(path.dirname(fromFile), specifier);
  } else {
    return null; // bare package import -- not ours to police
  }

  for (const ext of RESOLVE_EXTENSIONS) {
    const contents = readIfFile(base + ext);
    if (contents !== null) return contents;
  }
  for (const ext of RESOLVE_EXTENSIONS) {
    const contents = readIfFile(path.join(base, "index" + ext));
    if (contents !== null) return contents;
  }
  return readIfFile(base);
}

/** Is this reference the element name in JSX, i.e. rendering a component? */
function isJsxUsage(reference) {
  let node = reference.identifier;
  let parent = node.parent;
  while (parent && parent.type === "JSXMemberExpression") {
    node = parent;
    parent = parent.parent;
  }
  return (
    parent &&
    (parent.type === "JSXOpeningElement" || parent.type === "JSXClosingElement") &&
    parent.name === node
  );
}

const rule = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Disallow Server Components importing non-component values from \"use client\" modules",
    },
    schema: [
      {
        type: "object",
        properties: { srcRoot: { type: "string" } },
        additionalProperties: false,
      },
    ],
    messages: {
      clientValueInServer:
        "'{{name}}' is imported from '{{source}}', which is a \"use client\" module. A Server " +
        "Component does not receive the real value here -- it gets a client reference stub, so a " +
        "function throws at request time and a constant fails silently (see #196, #204). Move the " +
        "shared value into a plain module (e.g. @/lib/...) and re-export it from the client " +
        "component for client importers.",
    },
  },

  create(context) {
    const filename = context.filename ?? context.getFilename();
    if (!filename || filename === "<input>") return {};

    // Test files are not Server Components -- they run in vitest under jsdom,
    // where importing a hook out of a "use client" module is exactly what a
    // test is supposed to do. Caught by dogfooding: the rule flagged this
    // project's own use-selection.test.tsx on the first run.
    if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(filename)) return {};

    const sourceText = context.sourceCode.getText();
    // Only Server Components are at risk. A client module importing from
    // another client module is entirely fine.
    if (isClientSource(sourceText)) return {};

    const srcRoot = context.options?.[0]?.srcRoot ?? path.join(process.cwd(), "src");

    return {
      ImportDeclaration(node) {
        // Types are erased before runtime, so they never cross the boundary.
        if (node.importKind === "type") return;

        const targetSource = resolveImport(node.source.value, filename, srcRoot);
        if (targetSource === null || !isClientSource(targetSource)) return;

        for (const variable of context.sourceCode.getDeclaredVariables(node)) {
          const specifier = variable.defs[0]?.node;
          if (specifier?.importKind === "type") continue;

          // A binding used only as a JSX element name is a component being
          // rendered -- the supported, intended pattern.
          const references = variable.references;
          if (references.length > 0 && references.every(isJsxUsage)) continue;

          context.report({
            node: specifier ?? node,
            messageId: "clientValueInServer",
            data: { name: variable.name, source: node.source.value },
          });
        }
      },
    };
  },
};

export default rule;
