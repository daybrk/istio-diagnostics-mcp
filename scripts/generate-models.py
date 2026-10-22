import json,re
from pathlib import Path
s=json.load(open('docs/design/contracts/mcp.schema.json'))['$defs']; defs={}; generated=[]
rename={'Error':'APIError'}
def title(k):
 return ''.join({'id':'ID','uid':'UID','ids':'IDs','uids':'UIDs','ttl':'TTL'}.get(x,x.title()) for x in k.split('_'))
def typ(d,name):
 if '$ref' in d:
  key=d['$ref'].split('/')[-1]
  if s[key].get('type')=='object':return rename.get(key,key)
  return typ(s[key],name)
 t=d.get('type')
 if t=='array':return '[]'+typ(d['items'],name+'Item')
 if t=='object':
  emit(name,d);return name
 if t=='integer':return 'int'
 if t=='boolean':return 'bool'
 if t=='number':return 'float64'
 return 'string'
def emit(n,d):
 if n in defs:return
 defs[n]=True;lines=['type '+n+' struct {'];req=d.get('required',[])
 for k,v in d.get('properties',{}).items():
  tn=typ(v,n+title(k));optional=k not in req
  if optional and v.get('$ref','').split('/')[-1] in s and s[v['$ref'].split('/')[-1]].get('type')=='object':tn='*'+tn
  if optional and v.get('type')=='object':tn='*'+tn
  lines.append(title(k)+' '+tn+' `json:"'+k+(',omitempty' if optional else '')+'"`')
 lines.append('}');generated.append('\n'.join(lines))
for n,d in s.items():
 if d.get('type')=='object' and not(n.endswith('Input') or n.endswith('Output')):emit(rename.get(n,n),d)
Path('internal/core/models.go').write_text('// Code generated from docs/design/contracts/mcp.schema.json; DO NOT EDIT.\npackage core\n\n'+'\n\n'.join(generated)+'\n')
