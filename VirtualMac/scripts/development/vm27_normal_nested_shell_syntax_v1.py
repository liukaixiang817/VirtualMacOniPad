#!/usr/bin/env python3
"""Parse actual outer and quoted shell command bodies without executing them."""
import hashlib,pathlib,shlex,subprocess
SHELLS=('/var/jb/bin/sh','/bin/sh')

def tokens(source):
    lexer=shlex.shlex(source,posix=True,punctuation_chars=';&|(){}')
    lexer.whitespace_split=True
    return list(lexer)

def cleanup_literal(source):
    values=[]
    def walk(body,depth):
        if depth>8:raise ValueError('finite static assignment depth')
        words=tokens(body)
        values.extend(word.split('=',1)[1] for word in words if word.startswith('OWN_EXACT_CLEANUP_V4='))
        for i,word in enumerate(words[:-2]):
            if word in SHELLS and words[i+1]=='-c' and not words[i+2].startswith('$'):
                walk(words[i+2],depth+1)
    walk(source,0)
    if len(values)!=1 or not values[0]:raise ValueError('one actual static cleanup assignment required')
    return values[0]

def check_tree(label,source,output,shared_cleanup):
    output=pathlib.Path(output);records=[]
    def check(name,body,depth):
        if depth>8 or len(records)>=64 or len(body.encode())>262144:raise ValueError('finite syntax tree limit')
        stem=str(len(records))+'-'+name
        path=output/(stem+'.sh');path.write_text(body)
        tested=subprocess.run(['/bin/sh','-n',str(path)],capture_output=True,timeout=5)
        (output/(stem+'.stdout')).write_bytes(tested.stdout);(output/(stem+'.stderr')).write_bytes(tested.stderr)
        record=dict(label=name,depth=depth,path=str(path.resolve()),bytes=len(body.encode()),sha256=hashlib.sha256(body.encode()).hexdigest(),exit=tested.returncode,stderr=tested.stderr.decode(errors='replace'))
        records.append(record)
        words=tokens(body)
        actual=[word.split('=',1)[1] for word in words if word.startswith('OWN_EXACT_CLEANUP_V4=')]
        local=actual[0] if actual else shared_cleanup
        for i,word in enumerate(words[:-2]):
            if word not in SHELLS or words[i+1]!='-c':continue
            command=words[i+2]
            if command=='$OWN_EXACT_CLEANUP_V4':
                if not local:raise ValueError('dynamic cleanup command must bind actual static assignment')
                command=local
                child='cleanup-literal'
            elif command.startswith('$'):
                raise ValueError('unresolved dynamic shell body cannot pass syntax review')
            else:child='literal-sh-c'
            check(name+'-'+child,command,depth+1)
    check(label,source,0)
    return records
