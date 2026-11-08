/**
 * Minimal markdown renderer for AI Security Assistant answers.
 *
 * The assistant returns a constrained subset of markdown (bold, inline code,
 * bullet and numbered lists, and horizontal rules), so a focused renderer is
 * used instead of pulling in a full parser. Everything is rendered as React
 * elements rather than raw HTML, which removes any XSS risk from LLM output.
 */

function renderInline(text, keyPrefix) {
  const nodes = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;
  let index = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith('**')) {
      nodes.push(
        <strong key={`${keyPrefix}-b${index}`} className="text-gray-100 font-semibold">
          {token.slice(2, -2)}
        </strong>
      );
    } else {
      nodes.push(
        <code key={`${keyPrefix}-c${index}`} className="px-1.5 py-0.5 rounded bg-gray-800 text-accent-400 text-[0.85em] font-mono">
          {token.slice(1, -1)}
        </code>
      );
    }
    lastIndex = match.index + token.length;
    index += 1;
  }

  if (lastIndex < text.length) nodes.push(text.slice(lastIndex));
  return nodes;
}

export default function Markdown({ content, className = '' }) {
  if (!content) return null;

  const lines = String(content).split('\n');
  const blocks = [];
  let listItems = [];
  let listOrdered = false;

  const flushList = (key) => {
    if (listItems.length === 0) return;
    const ListTag = listOrdered ? 'ol' : 'ul';
    blocks.push(
      <ListTag
        key={`list-${key}`}
        className={`my-2 space-y-1.5 ${listOrdered ? 'list-decimal' : 'list-disc'} pl-5 marker:text-primary-400`}
      >
        {listItems.map((item, i) => (
          <li key={i} className="text-gray-300 leading-relaxed">{renderInline(item, `li-${key}-${i}`)}</li>
        ))}
      </ListTag>
    );
    listItems = [];
  };

  lines.forEach((rawLine, i) => {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();

    if (trimmed === '---') {
      flushList(i);
      blocks.push(<hr key={`hr-${i}`} className="my-4 border-gray-800" />);
      return;
    }

    if (trimmed === '') {
      flushList(i);
      return;
    }

    const bullet = trimmed.match(/^[-*]\s+(.*)$/);
    if (bullet) {
      if (listOrdered) flushList(i);
      listOrdered = false;
      listItems.push(bullet[1]);
      return;
    }

    const numbered = trimmed.match(/^\d+\.\s+(.*)$/);
    if (numbered) {
      if (!listOrdered) flushList(i);
      listOrdered = true;
      listItems.push(numbered[1]);
      return;
    }

    flushList(i);

    // A line that is entirely bold acts as a section heading.
    const heading = trimmed.match(/^\*\*(.+)\*\*:?$/);
    if (heading) {
      blocks.push(
        <h4 key={`h-${i}`} className="text-sm font-semibold text-primary-300 mt-3 mb-1">
          {heading[1]}
        </h4>
      );
      return;
    }

    const indented = rawLine.startsWith('   ') || rawLine.startsWith('\t');
    blocks.push(
      <p key={`p-${i}`} className={`text-gray-300 leading-relaxed ${indented ? 'pl-5 text-sm' : ''} my-1`}>
        {renderInline(trimmed, `p-${i}`)}
      </p>
    );
  });

  flushList('end');

  return <div className={`text-sm ${className}`}>{blocks}</div>;
}
