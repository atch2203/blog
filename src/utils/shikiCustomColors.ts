import type { ShikiTransformer, ThemedToken } from "shiki";

/**
 * Fine-grained colouring of code blocks, driven by the code fence meta string.
 *
 * ```http {2,5:#e06c75} {1:bg=#3a2f1a} "DATA HTTP/1.1":#e5c07b
 * ```
 *
 * - `{2,5:#e06c75}`     colour lines 2 and 5 (ranges allowed: `{2-4:red}`)
 * - `{1:bg=#3a2f1a}`    background of line 1
 * - `"foo bar":#e5c07b` colour every occurrence of the literal text `foo bar`,
 *                       even where it straddles several syntax tokens
 * - `"foo bar":bg=#3a2f1a` background of the literal text `foo bar` (foreground
 *                       colour left untouched)
 * - `/product/:#61afef` same thing; only for text with no `/` in it, since
 *                       markdown strips backslash escapes before we see the meta
 * - `"Host: a\n\nGET":#61afef` `\n` and `\t` stand for the real characters, so a
 *                       match may run across several lines
 * - `"W/\\"84e\\"":#61afef` `\\"` (a `\"` after markdown eats one backslash) lets
 *                       a quoted rule match text that itself contains `"`
 * - `title="our request"` caption above the block; wraps it in a `<figure>`
 *
 * Rules can be repeated freely; later ones win, so a word rule can repaint part
 * of a coloured line.
 */

type LineRule = { lines: Set<number>; color?: string; background?: string };
type WordRule = { text: string; color?: string; background?: string };

const LINE_RULE = /\{([\d,\s-]+):(bg=)?([^}\s]+)\}/g;
const WORD_RULE = /\/([^/\n]+)\/:(bg=)?([^\s]+)/g;
// Inner `\"` (written `\\"` in markdown) is consumed as an escape pair, so a
// bare `"` only ever ends the rule.
const QUOTED_WORD_RULE = /"((?:\\.|[^"\n\\])+)":(bg=)?([^\s]+)/g;
const TITLE_RULE = /(^|\s)title="([^"\n]*)"/;

/** Shown at a line end whose newline sits inside a background span. */
const NEWLINE_GLYPH = "↵";
const NEWLINE_GLYPH_COLOR = "#ffffff80";

/**
 * `\n` / `\t` stand for newline and tab; `\"` for a double quote so a quoted
 * rule can match text that itself contains `"`. Markdown eats a lone backslash
 * before `"`, so in the fence you write `\\"` — that reaches us as `\"`.
 */
function unescape(text: string): string {
  return text
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\"/g, '"');
}

function makeWordRule(text: string, bg: string | undefined, color: string): WordRule {
  const t = unescape(text);
  return bg ? { text: t, background: color } : { text: t, color };
}

function parseLines(spec: string): Set<number> {
  const lines = new Set<number>();
  for (const part of spec.split(",")) {
    const range = part.trim();
    if (!range) continue;
    const [start, end] = range.split("-").map(n => parseInt(n, 10));
    if (Number.isNaN(start)) continue;
    const last = end === undefined || Number.isNaN(end) ? start : end;
    for (let i = start; i <= last; i++) {
      lines.add(i);
    }
  }
  return lines;
}

function parseMeta(rawMeta: string) {
  const lineRules: LineRule[] = [];
  const wordRules: WordRule[] = [];

  // Pulled out first so the caption text is never read as a colour rule.
  const title = rawMeta.match(TITLE_RULE)?.[2];
  const meta = rawMeta.replace(TITLE_RULE, "");

  for (const [, spec, bg, color] of meta.matchAll(LINE_RULE)) {
    const lines = parseLines(spec);
    if (!lines.size) continue;
    lineRules.push(bg ? { lines, background: color } : { lines, color });
  }

  for (const [, text, bg, color] of meta.matchAll(QUOTED_WORD_RULE)) {
    wordRules.push(makeWordRule(text, bg, color));
  }

  for (const [, text, bg, color] of meta
    .replace(QUOTED_WORD_RULE, "")
    .matchAll(WORD_RULE)) {
    wordRules.push(makeWordRule(text, bg, color));
  }

  return { lineRules, wordRules, title };
}

type Span = { start: number; end: number; color?: string; background?: string };

/** Locate every occurrence of every word rule within the whole code block. */
function findSpans(text: string, rules: WordRule[]): Span[] {
  const spans: Span[] = [];
  for (const rule of rules) {
    if (!rule.text) continue;
    let i = text.indexOf(rule.text);
    while (i !== -1) {
      spans.push({
        start: i,
        end: i + rule.text.length,
        color: rule.color,
        background: rule.background,
      });
      i = text.indexOf(rule.text, i + rule.text.length);
    }
  }
  return spans;
}

/**
 * Recolour the parts of one line covered by `spans`, splitting tokens where a
 * span starts or ends mid-token. A match may cross both token and line
 * boundaries, so offsets are block-relative and `lineStart` says where this
 * line sits inside the block.
 */
function applySpans(
  tokens: ThemedToken[],
  spans: Span[],
  lineStart: number
): ThemedToken[] {
  if (!spans.length) return tokens;

  const out: ThemedToken[] = [];
  let blockOffset = lineStart;

  for (const token of tokens) {
    const length = token.content.length;
    const cuts = new Set([0, length]);

    for (const span of spans) {
      for (const cut of [span.start - blockOffset, span.end - blockOffset]) {
        if (cut > 0 && cut < length) cuts.add(cut);
      }
    }

    const sorted = [...cuts].sort((a, b) => a - b);
    for (let i = 0; i < sorted.length - 1; i++) {
      const [from, to] = [sorted[i], sorted[i + 1]];
      // Later rules win, so take the last colour/background covering this piece;
      // foreground and background are resolved independently.
      const covering = (s: Span) =>
        s.start <= blockOffset + from && blockOffset + from < s.end;
      const color = spans.findLast(s => covering(s) && s.color)?.color;
      const background = spans.findLast(s => covering(s) && s.background)?.background;
      out.push({
        ...token,
        content: token.content.slice(from, to),
        offset: token.offset + from,
        ...(color ? { color } : {}),
        ...(background ? { bgColor: background } : {}),
      });
    }

    blockOffset += length;
  }

  return out;
}

export function transformerCustomColors(): ShikiTransformer {
  return {
    name: "custom-colors",

    tokens(lines) {
      const meta = this.options.meta?.__raw;
      if (!meta) return;
      const { lineRules, wordRules } = parseMeta(meta);
      if (!lineRules.length && !wordRules.length) return;

      // Word rules match against the whole block, so they can span line breaks.
      const lineTexts = lines.map(tokens =>
        tokens.map(token => token.content).join("")
      );
      const spans = findSpans(lineTexts.join("\n"), wordRules);

      let lineStart = 0;
      return lines.map((tokens, index) => {
        const lineNumber = index + 1;
        let out = tokens;

        for (const rule of lineRules) {
          if (rule.color && rule.lines.has(lineNumber)) {
            out = out.map(token => ({ ...token, color: rule.color }));
          }
        }

        out = applySpans(out, spans, lineStart);

        // The newline joining this line to the next has no width, so a
        // background that runs through it would visually stop at the line end.
        // Mark it with a glyph carrying the same background.
        const newlinePos = lineStart + lineTexts[index].length;
        const isLastLine = index === lines.length - 1;
        const newlineSpan = isLastLine
          ? undefined
          : spans.findLast(
              s => s.background && s.start <= newlinePos && newlinePos < s.end
            );
        if (newlineSpan) {
          out = [
            ...out,
            {
              content: NEWLINE_GLYPH,
              offset: newlinePos,
              color: NEWLINE_GLYPH_COLOR,
              bgColor: newlineSpan.background,
            },
          ];
        }

        lineStart += lineTexts[index].length + 1; // + the "\n" join

        return out;
      });
    },

    line(node, line) {
      const meta = this.options.meta?.__raw;
      if (!meta) return;

      for (const rule of parseMeta(meta).lineRules) {
        if (rule.background && rule.lines.has(line)) {
          this.addClassToHast(node, "highlighted");
          node.properties.style =
            `${node.properties.style ?? ""};background-color:${rule.background}`.replace(
              /^;/,
              ""
            );
        }
      }
    },

    root(node) {
      const meta = this.options.meta?.__raw;
      const title = meta ? parseMeta(meta).title : undefined;
      if (!title) return;

      node.children = [
        {
          type: "element",
          tagName: "figure",
          properties: { class: "code-figure" },
          children: [
            {
              type: "element",
              tagName: "figcaption",
              properties: { class: "code-title" },
              children: [{ type: "text", value: title }],
            },
            ...node.children.filter(child => child.type === "element"),
          ],
        },
      ];
    },
  };
}
