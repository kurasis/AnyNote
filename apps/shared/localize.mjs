// Only text nodes captured before account/content loading are translated. There
// is no observer that could rewrite a user value, fingerprint or recovery secret.
import {russian} from './russian.mjs';

export function createLocalizer() {
  let language = navigator.language?.startsWith('ru') ? 'ru' : 'en';
  const text = value => language === 'ru' && Object.hasOwn(russian, value) ? russian[value] : value;
  const template = (strings, ...values) => {
    const key = strings.join('{}'), translated = text(key).split('{}');
    const parts = translated.length === values.length + 1 ? translated : strings;
    return parts.map((part, index) => part + (index < values.length ? String(values[index]) : '')).join('');
  };
  const records = [];
  for (const element of document.querySelectorAll('h1,h2,h3,p,label,button,summary,a,legend')) {
    for (const node of element.childNodes) {
      if (node.nodeType !== 3 || !node.textContent.trim()) continue;
      records.push({node, original: node.textContent, rendered: node.textContent});
    }
  }
  const label = document.createElement('label');
  label.htmlFor = 'shell-language'; label.textContent = 'Language / Язык';
  const select = document.createElement('select'); select.id = 'shell-language';
  for (const [value, title] of [['en', 'English'], ['ru', 'Русский']]) {
    const option = document.createElement('option'); option.value = value; option.textContent = title;
    select.append(option);
  }
  label.append(select); document.querySelector('main').prepend(label);
  const apply = () => {
    document.documentElement.lang = language; select.value = language;
    for (const record of records) {
      // A replaced/disconnected or programmatically updated node is runtime
      // output. Leave it alone instead of restoring a stale initial label.
      if (!record.node.isConnected || record.node.textContent !== record.rendered) continue;
      record.rendered = record.original.replace(record.original.trim(), text(record.original.trim()));
      record.node.textContent = record.rendered;
    }
  };
  select.onchange = () => { language = select.value; apply(); };
  apply();
  const date = value => {
    if (value === null || value === undefined) return text('unknown');
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) ? new Intl.DateTimeFormat(language, {dateStyle: 'medium', timeStyle: 'short'}).format(parsed) : text('unknown');
  };
  return {text, template, date, language: () => language};
}
