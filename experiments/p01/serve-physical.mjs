// Explicit local/private HTTPS synthetic server. Does not deploy or obtain certificates.
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { serve } from './transport.mjs';
import './build.mjs';

const {values}=parseArgs({options:{cert:{type:'string'},key:{type:'string'},host:{type:'string',default:'127.0.0.1'},port:{type:'string',default:'8443'}}});
if(!values.cert||!values.key)throw new Error('Provide a trusted test HTTPS certificate/key via --cert and --key; never commit them.');
const port=Number(values.port);if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid port');
const scratch=await mkdtemp(join(tmpdir(),'anynote-p01-physical-'));
let transport;
try{transport=await serve({scratch,tls:{cert:await readFile(values.cert),key:await readFile(values.key),minVersion:'TLSv1.2'},host:values.host,port});}
catch(error){await rm(scratch,{recursive:true,force:true});throw error;}
console.log('Private HTTPS synthetic harness listening; use the configured trusted host /physical/ path. Not a deployment or physical pass.');
let stopping=false;
async function stop(){if(stopping)return;stopping=true;await new Promise(resolve=>transport.server.close(resolve));await rm(scratch,{recursive:true,force:true});}
process.on('SIGINT',stop);process.on('SIGTERM',stop);
