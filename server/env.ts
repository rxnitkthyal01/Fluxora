import fs from 'node:fs';
import path from 'node:path';

const file=path.resolve(process.cwd(),'.env');
if(fs.existsSync(file)){
  for(const line of fs.readFileSync(file,'utf8').split(/\r?\n/)){
    const match=line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if(!match||process.env[match[1]]!==undefined)continue;
    let value=match[2];
    if((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")))value=value.slice(1,-1);
    else value=value.replace(/\s+#.*$/,'').trim();
    process.env[match[1]]=value;
  }
}
