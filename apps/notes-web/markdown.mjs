import MarkdownIt from 'markdown-it';
// Maintained parser, closed DOM renderer. HTML is literal and remote images are never fetched.
const parser=new MarkdownIt({html:false,linkify:false,typographer:false,maxNesting:20});
const elements=new Map([['paragraph','p'],['heading','h2'],['bullet_list','ul'],['ordered_list','ol'],['list_item','li'],['blockquote','blockquote'],['strong','strong'],['em','em'],['s','s']]);
export function safeLink(value){
 try{const u=new URL(value);return ['https:','http:'].includes(u.protocol)&&!u.username&&!u.password?u.href:null;}catch{return null;}
}
export function renderMarkdown(target,text){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>2097152)throw Error('RESOURCE_LIMIT');
 const tokens=parser.parse(text,{});let count=0;const fragment=document.createDocumentFragment(),stack=[fragment];
 function append(node){if(++count>20000)throw Error('PREVIEW_LIMIT');stack.at(-1).append(node);}
 function walk(items){
  for(const t of items){
   if(t.type==='inline'){walk(t.children??[]);continue;}
   if(t.type==='text'||t.type==='html_inline'||t.type==='html_block'){append(document.createTextNode(t.content));continue;}
   if(t.type==='softbreak'||t.type==='hardbreak'){append(document.createElement('br'));continue;}
   if(t.type==='code_inline'){const e=document.createElement('code');e.textContent=t.content;append(e);continue;}
   if(t.type==='fence'||t.type==='code_block'){const p=document.createElement('pre'),e=document.createElement('code');e.textContent=t.content;p.append(e);append(p);continue;}
   if(t.type==='image'){append(document.createTextNode(t.content||'[image]'));continue;}
   if(t.type==='hr'){append(document.createElement('hr'));continue;}
   if(t.nesting===-1){if(stack.length>1)stack.pop();continue;}
   if(t.nesting===1){
    let e;
    if(t.type==='link_open'){const href=safeLink(t.attrGet('href')??'');e=document.createElement(href?'a':'span');if(href){e.href=href;e.rel='noopener noreferrer';e.target='_blank';}}
    else{const name=elements.get(t.type.replace(/_open$/,''));if(!name){append(document.createTextNode(t.content));continue;}e=document.createElement(name);if(t.type==='heading_open'&&/^h[1-6]$/.test(t.tag))e=document.createElement(t.tag);}
    append(e);if(stack.length>=32)throw Error('PREVIEW_LIMIT');stack.push(e);continue;
   }
   append(document.createTextNode(t.content??''));
  }
 }
 try{walk(tokens);target.replaceChildren(fragment);}catch(e){target.replaceChildren();if(e.message==='PREVIEW_LIMIT'){target.textContent='This preview is too large. The complete text is available in the editor.';}else throw e;}
}
