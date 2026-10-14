import {PreviewClient} from '../../packages/content-browser/preview-client.mjs';
import {PREVIEW_LIMITS} from '../../packages/content-browser/preview-bounds.mjs';
const make=(tag,id,text)=>{const node=document.createElement(tag);if(id)node.id=id;if(text)node.textContent=text;return node;};
export function contentUI({vault,getGroup,text,run,open,files,authorize}){
  const section=make('fieldset','content-tools'),legend=make('legend',null,text('content_tools'));
  const query=make('input','vault-search');query.type='search';query.autocomplete='off';query.maxLength=256;query.setAttribute('aria-label',text('vault_search'));
  const scoped=make('input','search-this-group');scoped.type='checkbox';scoped.checked=true;
  const scopeLabel=make('label',null,text('search_this_group'));scopeLabel.prepend(scoped);
  const state=make('p','search-coverage'),results=make('ul','search-results'),view=make('section','file-preview');
  const search=make('button','search-vault',text('vault_search')),rebuild=make('button','rebuild-search',text('rebuild_search'));
  const known=make('p',null,text('search_known_only'));section.append(legend,query,scopeLabel,search,rebuild,known,state,results,view);document.getElementById('workspace').append(section);
  const renderer=new PreviewClient();let generation=1,thumbnail;
  const command=(op,x={})=>vault.notes('content',[op,x]);
  const coverage=value=>{state.textContent=text('search_indexed')+' '+value.indexed+' / '+value.known+'; '+text('search_unavailable')+' '+value.unavailable+'; '+text('search_unanchored')+' '+value.unanchored+'; '+text('search_stale')+' '+value.stale+'; '+text('search_bounded')+' '+value.bounded;if(value.rebuild_required)state.textContent+=' · '+text('search_rebuild_required');};
  const scope=()=>scoped.checked&&getGroup()?{group_id:getGroup()}:{};
  search.onclick=()=>run(async()=>{const seen=generation,value=await command('search',{...scope(),query:query.value});if(seen!==generation)return;coverage(value.coverage);results.replaceChildren();
    for(const result of value.results){const li=make('li'),button=make('button',null,result.title||result.object_id);button.onclick=()=>run(()=>open(result));li.append(button,make('span',null,' · '+result.snippet+(result.historical?' · '+text('historical_result'):'')));results.append(li);}
    if(!value.results.length&&!value.rebuild_required)results.append(make('li',null,text('no_local_matches')));
  });
  rebuild.onclick=()=>run(async()=>{const seen=generation;await command('clearIndex',{confirm:true});let after=0,indexed=0,skipped=0;
    do{const page=await command('catalog',{after});for(let n=0;n<page.items.length;n+=16){if(seen!==generation||document.hidden)throw Error('RESUME_REQUIRED');const done=await command('index',{revision_ids:page.items.slice(n,n+16).map(i=>i.revision_id)});indexed+=done.indexed;skipped+=done.skipped?.length??0;state.textContent=text('search_indexed')+' '+indexed+' / '+page.known+'; '+text('search_unavailable')+' '+skipped;}after=page.next;}while(after!==null);
    coverage(await command('coverage',scope()));
  });
  query.onkeydown=event=>{if(event.key==='Enter'){event.preventDefault();search.click();}};
  return {
    translate(){legend.textContent=text('content_tools');search.textContent=text('vault_search');rebuild.textContent=text('rebuild_search');known.textContent=text('search_known_only');},
    close(){generation++;renderer.close();query.value='';state.textContent='';results.replaceChildren();view.replaceChildren();thumbnail?.fill(0);thumbnail=undefined;},
    async preview(group_id,file_version_id){
      const seen=generation;renderer.close();thumbnail?.fill(0);thumbnail=undefined;view.replaceChildren();await authorize(group_id);
      const manager=files(),record=await manager.transport.call('/files/'+file_version_id+'/manifest'),metadata=await manager.command('observe',{group_id,file_version_id,record});
      const size=Number(record.envelope.header.framing.plaintext_bytes);if(size>PREVIEW_LIMITS.imageBytes)throw Error('PREVIEW_RESOURCE_LIMIT');
      let bytes=new Uint8Array(size),offset=0,complete=false;
      try{await manager.download(group_id,file_version_id,{write:part=>{if(seen!==generation||offset+part.length>size)throw Error('PREVIEW_CANCELLED');bytes.set(part,offset);offset+=part.length;},finish:()=>{if(offset!==size)throw Error('PREVIEW_CANCELLED');complete=true;},abort:()=>{bytes.fill(0);}});
        if(!complete||seen!==generation||document.hidden)throw Error('PREVIEW_CANCELLED');
        const kind=bytes[0]===37&&bytes[1]===80&&bytes[2]===68&&bytes[3]===70?'pdf':bytes[0]===137||bytes[0]===255||bytes[0]===82&&bytes[1]===73?'image':'text';
        const source=bytes;bytes=undefined;let result;try{result=await renderer.render(kind,source);}finally{if(source.byteLength)source.fill(0);}if(seen!==generation){result.bitmap?.close();result.thumbnail?.fill(0);throw Error('PREVIEW_CANCELLED');}
        view.append(make('h3',null,metadata.name),make('p',null,text('preview_bounded')));
        if(result.bitmap){const canvas=make('canvas');canvas.width=result.bitmap.width;canvas.height=result.bitmap.height;canvas.getContext('2d').drawImage(result.bitmap,0,0);result.bitmap.close();view.append(canvas);}
        if(result.text!==undefined){const pre=make('pre',null,result.text);view.append(pre);}thumbnail=result.thumbnail;
      }finally{bytes?.fill(0);}
    },
  };
}
