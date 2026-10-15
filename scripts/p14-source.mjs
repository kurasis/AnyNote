// Test-receipt source stamp: a commit or dirty-to-clean transition cannot relabel a running test.
import {execFileSync} from 'node:child_process';
export function sourceStamp(root){
 const git=(...args)=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
 const head=git('rev-parse','HEAD'),dirty=git('status','--porcelain')!=='';
 return ()=>({source_commit:head,source_tree_dirty:dirty||git('rev-parse','HEAD')!==head||git('status','--porcelain')!==''});
}
