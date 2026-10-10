// Only short-lived capabilities for generated synthetic exports; never vault keys or bytes.
export function ticketStore(scope){
  const name=`anynote-p01-download-tickets-v1:${new URL(scope).pathname}`;
  let database;
  function open(){
    return database??=new Promise((resolve,reject)=>{
      const request=indexedDB.open(name,1);
      request.onupgradeneeded=()=>request.result.createObjectStore('tickets',{keyPath:'token'});
      request.onsuccess=()=>resolve(request.result);
      request.onerror=()=>reject(new Error('Synthetic download ticket storage unavailable'));
      request.onblocked=()=>reject(new Error('Synthetic ticket database blocked'));
    });
  }
  async function transaction(action){
    const db=await open();
    return new Promise((resolve,reject)=>{
      const tx=db.transaction('tickets','readwrite');let value;
      tx.oncomplete=()=>resolve(value);tx.onabort=()=>reject(new Error('Synthetic ticket transaction failed'));
      action(tx.objectStore('tickets'),result=>{value=result;},tx);
    });
  }
  return {
    issue:ticket=>transaction((store,done,tx)=>{
      let count=0;const cursor=store.openCursor();
      cursor.onsuccess=()=>{
        const entry=cursor.result;
        if(entry){
          if(entry.value.expires<Date.now()||entry.value.client===ticket.client)entry.delete();else count++;
          entry.continue();
        }else if(count>=64)tx.abort();
        else {store.put(ticket);done(ticket.token);}
      };
    }),
    consume:token=>transaction((store,done)=>{
      const request=store.get(token);
      request.onsuccess=()=>{
        const ticket=request.result;store.delete(token);
        done(ticket?.expires>=Date.now()?ticket:null);
      };
    })
  };
}
