// Minimal auto-escaping templates. Interpolated values are escaped unless they
// are Html (produced by html`` or raw()), so user-controlled text such as a
// secret's notes or an agent's reason can never inject markup.
export class Html {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };

export function escape(value: string): string {
  return value.replace(/[&<>"'`]/g, c => ESCAPES[c]!);
}

type Value = Html | string | number | boolean | null | undefined | Value[];

function render(value: Value): string {
  if (value === null || value === undefined || value === false) return '';
  if (Array.isArray(value)) return value.map(render).join('');
  if (value instanceof Html) return value.value;
  return escape(String(value));
}

export function html(strings: TemplateStringsArray, ...values: Value[]): Html {
  let out = strings[0] ?? '';
  values.forEach((v, i) => {
    out += render(v) + (strings[i + 1] ?? '');
  });
  return new Html(out);
}

export function raw(value: string): Html {
  return new Html(value);
}
